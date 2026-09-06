"""Static PDF triage — recover objects a strict parser refuses, flag the traps,
decrypt, and dump inline images. Never renders or executes anything.

A "devilish" PDF weaponises the gap between what a lenient viewer *recovers*
and what a strict parser *rejects*: no xref/EOF, an object defined twice, a
key hidden behind name-hex (`/Root` vs `/#52#6F#6F#74`), so different renderers
resolve a different document. A normal PDF library silently picks one
interpretation — hiding exactly the ambiguity that matters. So recon here is a
raw-bytes pass whose whole job is to *surface* those ambiguities, not resolve
them away.

`pdf_tour` is the one-shot: recon + trap report, and when the file is
encrypted (Standard handler, R2-R6) it derives the key from the empty/supplied
password, decrypts the streams, and lists any inline images hidden inside —
because those live *inside* the encrypted content, one call has to walk the
whole chain to be useful.
"""
from __future__ import annotations

import binascii
import hashlib
import logging
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from chimera.unpacking import pdfcrypt

logger = logging.getLogger(__name__)

_MAX_STREAM = 64 * 1024 * 1024  # zip-bomb guard on any single inflate

# Inline-image filter abbreviations -> canonical, and which are terminal codecs
# (image formats we surface as-is rather than decode).
_FILTER_ALIASES = {
    "AHx": "ASCIIHexDecode", "A85": "ASCII85Decode", "LZW": "LZWDecode",
    "Fl": "FlateDecode", "RL": "RunLengthDecode", "CCF": "CCITTFaxDecode",
    "DCT": "DCTDecode",
}
_TERMINAL_CODEC = {
    "DCTDecode": "jpeg", "CCITTFaxDecode": "ccitt", "JPXDecode": "jpx",
    "JBIG2Decode": "jbig2", "LZWDecode": "lzw",
}
_KEY_ALIASES = {"W": "W", "Width": "W", "H": "H", "Height": "H",
                "BPC": "BPC", "BitsPerComponent": "BPC", "CS": "CS",
                "ColorSpace": "CS", "F": "F", "Filter": "F", "L": "L",
                "Length": "L", "IM": "IM", "ImageMask": "IM"}


# --------------------------------------------------------------------------- #
# dataclasses
# --------------------------------------------------------------------------- #
@dataclass
class PdfObject:
    num: int
    gen: int
    dict_bytes: bytes
    stream: bytes | None
    offset: int

    @property
    def type(self) -> str | None:
        m = re.search(rb"/Type\s*/([A-Za-z0-9]+)", self.dict_bytes)
        return m.group(1).decode("latin-1") if m else None


@dataclass
class RootRef:
    key: str          # raw trailer key, e.g. "/Root" or "/#52#6F#6F#74"
    num: int
    gen: int
    type: str | None  # resolved /Type of the target object


@dataclass
class Trap:
    kind: str
    detail: str


@dataclass
class PdfRecon:
    version: str
    objects: dict
    roots: list
    traps: list
    encrypt_ref: tuple | None
    id0: bytes = b""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "object_count": len(self.objects),
            "objects": [f"{n} {g}" for (n, g) in sorted(self.objects)],
            "roots": [{"key": r.key, "target": f"{r.num} {r.gen}",
                       "type": r.type} for r in self.roots],
            "traps": [{"kind": t.kind, "detail": t.detail} for t in self.traps],
            "encrypted": self.encrypt_ref is not None,
        }


@dataclass
class InlineImage:
    params: dict
    data: bytes
    codec: str

    def to_dict(self) -> dict:
        return {"params": self.params, "codec": self.codec,
                "size": len(self.data),
                "sha256": hashlib.sha256(self.data).hexdigest()}


@dataclass
class PdfTour:
    recon: PdfRecon
    encrypted: bool
    key_recovered: bool
    images: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.recon.to_dict()
        d["encrypted"] = self.encrypted
        d["key_recovered"] = self.key_recovered
        d["images"] = [im.to_dict() for im in self.images]
        d["notes"] = self.notes
        return d


# --------------------------------------------------------------------------- #
# low-level parsing helpers
# --------------------------------------------------------------------------- #
def _decode_name(tok: str) -> str:
    """Decode PDF name `#XX` hex escapes: `#52#6F#6F#74` -> `Root`."""
    return re.sub(r"#([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), tok)


def _strip_comments(text: bytes) -> bytes:
    """Drop `%`-to-EOL comments. Only safe on comment-legal text (no streams)."""
    return re.sub(rb"%[^\r\n]*", b"", text)


def _dict_end(data: bytes, i: int) -> int:
    """Index just past the `>>` matching the `<<` at data[i], skipping strings."""
    depth = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c == 0x28:  # '(' literal string — skip balanced, honour escapes
            i += 1
            d = 1
            while i < n and d:
                if data[i] == 0x5C:
                    i += 2
                    continue
                if data[i] == 0x28:
                    d += 1
                elif data[i] == 0x29:
                    d -= 1
                i += 1
            continue
        if c == 0x3C and data[i + 1:i + 2] == b"<":
            depth += 1
            i += 2
            continue
        if c == 0x3E and data[i + 1:i + 2] == b">":
            depth -= 1
            i += 2
            if depth == 0:
                return i
            continue
        i += 1
    return n


def _pdf_string_after(dict_bytes: bytes, key: bytes) -> bytes | None:
    """Value of `key` when it's a literal `( )` or hex `< >` string."""
    idx = dict_bytes.find(key)
    if idx < 0:
        return None
    i = idx + len(key)
    while i < len(dict_bytes) and dict_bytes[i] in b" \r\n\t":
        i += 1
    if dict_bytes[i:i + 1] == b"(":
        out = bytearray()
        i += 1
        d = 1
        esc = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12,
               0x28: 40, 0x29: 41, 0x5C: 92}
        while i < len(dict_bytes) and d:
            c = dict_bytes[i]
            if c == 0x5C:
                nb = dict_bytes[i + 1]
                if nb in esc:
                    out.append(esc[nb]); i += 2
                elif 0x30 <= nb <= 0x37:
                    j = i + 1; o = b""
                    while j < len(dict_bytes) and len(o) < 3 and 0x30 <= dict_bytes[j] <= 0x37:
                        o += dict_bytes[j:j + 1]; j += 1
                    out.append(int(o, 8) & 0xFF); i = j
                elif nb in (0x0A, 0x0D):
                    i += 2
                else:
                    out.append(nb); i += 2
            elif c == 0x28:
                d += 1; out.append(c); i += 1
            elif c == 0x29:
                d -= 1; i += 1
                if d:
                    out.append(c)
            else:
                out.append(c); i += 1
        return bytes(out)
    if dict_bytes[i:i + 1] == b"<":
        j = dict_bytes.find(b">", i)
        h = re.sub(rb"\s", b"", dict_bytes[i + 1:j])
        if len(h) % 2:
            h += b"0"
        try:
            return binascii.unhexlify(h)
        except binascii.Error:
            return None
    return None


# --------------------------------------------------------------------------- #
# recon + trap detection
# --------------------------------------------------------------------------- #
def recon(data: bytes) -> PdfRecon:
    version = "?"
    m = re.match(rb"%PDF-(\d+\.\d+)", data)
    if m:
        version = m.group(1).decode("latin-1")

    objects: dict = {}
    traps: list = []
    seen_dup: set = set()

    for m in re.finditer(rb"(\d+)\s+(\d+)\s+obj\b", data):
        start = m.start()
        line_start = data.rfind(b"\n", 0, start) + 1
        if b"%" in data[line_start:start]:      # commented-out object header
            traps.append(Trap("commented_object",
                              f"{m.group(1).decode()} {m.group(2).decode()} obj (commented)"))
            continue
        num, gen = int(m.group(1)), int(m.group(2))
        body_start = m.end()
        di = data.find(b"<<", body_start)
        dict_bytes, stream = b"", None
        endobj0 = data.find(b"endobj", body_start)
        if endobj0 < 0:                        # last object may omit endobj
            endobj0 = len(data)
        if 0 <= di < endobj0:
            de = _dict_end(data, di)
            dict_bytes = data[di:de]
            sm = re.compile(rb"stream\r?\n").search(data, de)
            endobj = data.find(b"endobj", de)
            if sm and sm.start() < (endobj if endobj >= 0 else len(data)):
                se = data.find(b"endstream", sm.end())
                stream = data[sm.end():se] if se >= 0 else data[sm.end():]
        if (num, gen) in objects:
            if (num, gen) not in seen_dup:
                traps.append(Trap("duplicate_object", f"{num} {gen} obj defined more than once"))
                seen_dup.add((num, gen))
            continue
        objects[(num, gen)] = PdfObject(num, gen, dict_bytes, stream, start)

    # Name-hex-obfuscated keys anywhere in object dicts or the trailer.
    for chunk in [o.dict_bytes for o in objects.values()] + [_trailer_bytes(data)]:
        for hm in re.finditer(rb"/([A-Za-z0-9]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*)", chunk):
            raw = "/" + hm.group(1).decode("latin-1")
            traps.append(Trap("name_hex_key", f"{raw} decodes to /{_decode_name(hm.group(1).decode('latin-1'))}"))

    # /Root references (comment-stripped trailer so split/hidden refs still parse).
    roots, root_targets = [], set()
    trailer = _strip_comments(_trailer_bytes(data))
    for rm in re.finditer(rb"(/[^\s/<>\[\]()]+)\s+(\d+)\s+(\d+)\s+R", trailer):
        key = rm.group(1).decode("latin-1")
        if _decode_name(key.lstrip("/")) == "Root":
            num, gen = int(rm.group(2)), int(rm.group(3))
            tgt = objects.get((num, gen))
            roots.append(RootRef(key, num, gen, tgt.type if tgt else None))
            root_targets.add((num, gen))
    if len(root_targets) > 1:
        traps.append(Trap("multiple_roots",
                          "trailer resolves to multiple /Root targets: "
                          + ", ".join(f"{n} {g}" for n, g in sorted(root_targets))))

    if b"startxref" not in data:
        traps.append(Trap("missing_xref", "no startxref / cross-reference table"))
    if b"%%EOF" not in data:
        traps.append(Trap("missing_eof", "no %%EOF marker"))

    encrypt_ref = None
    em = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", trailer)
    if em:
        encrypt_ref = (int(em.group(1)), int(em.group(2)))

    id0 = b""
    idm = re.search(rb"/ID\s*\[\s*<([0-9A-Fa-f]*)>", trailer)
    if idm:
        try:
            id0 = binascii.unhexlify(idm.group(1) + (b"0" if len(idm.group(1)) % 2 else b""))
        except binascii.Error:
            id0 = b""

    return PdfRecon(version, objects, roots, traps, encrypt_ref, id0)


def _trailer_bytes(data: bytes) -> bytes:
    idx = data.rfind(b"trailer")
    return data[idx:] if idx >= 0 else b""


# --------------------------------------------------------------------------- #
# inline images
# --------------------------------------------------------------------------- #
def _parse_inline_params(blob: bytes) -> dict:
    params: dict = {}
    # Pair each /Key with its following value (name, array, or number).
    flat = re.findall(rb"/[A-Za-z0-9]+|\[[^\]]*\]|-?\d+", blob)
    i = 0
    while i < len(flat) - 1:
        t = flat[i]
        if t.startswith(b"/"):
            key = _KEY_ALIASES.get(t[1:].decode("latin-1"), t[1:].decode("latin-1"))
            v = flat[i + 1]
            if v.startswith(b"["):
                params[key] = [x.decode("latin-1") for x in re.findall(rb"/([A-Za-z0-9]+)", v)]
            elif v.startswith(b"/"):
                params[key] = v[1:].decode("latin-1")
            else:
                try:
                    params[key] = int(v)
                except ValueError:
                    params[key] = v.decode("latin-1")
            i += 2
        else:
            i += 1
    return params


def _decode_ahx(data: bytes) -> bytes:
    h = re.sub(rb"\s", b"", data.split(b">", 1)[0])
    if len(h) % 2:
        h += b"0"
    return binascii.unhexlify(h)


def _decode_a85(data: bytes) -> bytes:
    import base64
    body = data.split(b"~>", 1)[0]
    return base64.a85decode(re.sub(rb"\s", b"", body))


def _decode_rl(data: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(data):
        n = data[i]; i += 1
        if n == 128:
            break
        if n < 128:
            out += data[i:i + n + 1]; i += n + 1
        else:
            out += bytes([data[i]]) * (257 - n); i += 1
    return bytes(out)


def _apply_filters(data: bytes, filters: list) -> tuple[bytes, str]:
    codec = "raw"
    for f in filters:
        canon = _FILTER_ALIASES.get(f, f)
        if canon in _TERMINAL_CODEC:
            codec = _TERMINAL_CODEC[canon]
            break
        if canon == "ASCIIHexDecode":
            data = _decode_ahx(data)
        elif canon == "ASCII85Decode":
            data = _decode_a85(data)
        elif canon == "FlateDecode":
            data = zlib.decompressobj().decompress(data, _MAX_STREAM)
        elif canon == "RunLengthDecode":
            data = _decode_rl(data)
    return data, codec


def inline_images(content: bytes) -> list:
    images: list = []
    for m in re.finditer(rb"\bBI\b(.*?)\bID\b", content, re.S):
        params = _parse_inline_params(m.group(1))
        data_start = m.end()
        if content[data_start:data_start + 1] in (b" ", b"\r", b"\n", b"\t"):
            data_start += 1
        em = re.compile(rb"\s(EI)(\s|$)").search(content, data_start)
        raw = content[data_start:em.start()] if em else content[data_start:]
        filt = params.get("F", [])
        filt = [filt] if isinstance(filt, str) else filt
        try:
            data, codec = _apply_filters(raw, filt)
        except (binascii.Error, ValueError, zlib.error) as e:
            logger.debug("inline image filter decode failed: %s", e)
            data, codec = raw, "raw"
        images.append(InlineImage(params, data, codec))
    return images


# --------------------------------------------------------------------------- #
# encryption wiring + one-shot tour
# --------------------------------------------------------------------------- #
def _build_handler(enc: PdfObject, id0: bytes) -> pdfcrypt.SecurityHandler | None:
    d = enc.dict_bytes
    def num(k, default):
        mm = re.search(k + rb"\s+(-?\d+)", d)
        return int(mm.group(1)) if mm else default
    V = num(rb"/V", 0); R = num(rb"/R", 0)
    length = num(rb"/Length", 0)
    P = num(rb"/P", 0)
    cfm = "V2"
    cm = re.search(rb"/CFM\s*/([A-Za-z0-9]+)", d)
    if cm:
        cfm = cm.group(1).decode("latin-1")
    elif V >= 5:
        cfm = "AESV3"
    enc_meta = b"/EncryptMetadata false" not in d
    return pdfcrypt.SecurityHandler(
        V=V, R=R, length=length, P=P,
        O=_pdf_string_after(d, b"/O") or b"",
        U=_pdf_string_after(d, b"/U") or b"",
        UE=_pdf_string_after(d, b"/UE") or b"",
        OE=_pdf_string_after(d, b"/OE") or b"",
        id0=id0, encrypt_metadata=enc_meta, cfm=cfm,
    )


def pdf_tour(source, password: bytes = b"", extract_images_dir=None) -> PdfTour:
    """Recon + traps, and (if encrypted) decrypt streams and list inline images."""
    if isinstance(source, (str, Path)):
        data = Path(source).read_bytes()
    else:
        data = source
    if isinstance(password, str):
        password = password.encode()

    r = recon(data)
    notes: list = []
    encrypted = r.encrypt_ref is not None
    handler = None
    key_recovered = False

    if encrypted and r.encrypt_ref in r.objects:
        try:
            handler = _build_handler(r.objects[r.encrypt_ref], r.id0)
            key = handler.file_key(password)
            key_recovered = key is not None
            if not key_recovered:
                notes.append("encrypted: password did not validate against /U "
                             "(try a different --password)")
        except pdfcrypt.PdfCryptError as e:
            notes.append(str(e))

    images: list = []
    for (n, g), obj in r.objects.items():
        if obj.stream is None:
            continue
        raw = obj.stream
        if handler is not None and key_recovered:
            try:
                raw = handler.decrypt(n, g, raw)
            except pdfcrypt.PdfCryptError as e:
                notes.append(str(e)); continue
        content = raw
        if b"FlateDecode" in obj.dict_bytes:
            try:
                content = zlib.decompressobj().decompress(raw, _MAX_STREAM)
            except zlib.error:
                content = raw
        if b"BI" in content and b"ID" in content:
            images.extend(inline_images(content))

    if extract_images_dir and images:
        outdir = Path(extract_images_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        ext = {"jpeg": "jpg", "raw": "bin"}
        for i, im in enumerate(images):
            (outdir / f"inline_{i}.{ext.get(im.codec, im.codec)}").write_bytes(im.data)
        notes.append(f"wrote {len(images)} inline image(s) to {outdir}")

    return PdfTour(r, encrypted, key_recovered, images, notes)
