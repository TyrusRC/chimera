"""Legacy PKZIP: ZipCrypto (traditional PKWARE) decryption + Reduce (method 2-5)
decompression — the old formats stdlib `zipfile` refuses.

A CTF ZIP can use the obsolete **Reduce** compression (method 2-5) and
**ZipCrypto** traditional encryption (`unzip`/`7z`/Python zipfile all fail on
these). FLARE-On 13 ch3 hid an answer in exactly such a `flag.txt` (method-2
Reduce + ZipCrypto, password `infected`). This implements both, as pure byte
functions (no I/O), so a carved local-file entry can be recovered.

Reduce is the PKWARE unreduce algorithm (follower-sets + an LZ expansion with a
DLE escape); ZipCrypto is the 3-key PKWARE stream cipher. Shrink (method 1) and
Implode (6) are not implemented — add when a target needs them.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path


def _crc32_byte(crc: int, b: int) -> int:
    return (crc >> 8) ^ _CRC32_TABLE[(crc ^ b) & 0xFF]


# Standard zlib/PKZIP CRC-32 table.
def _make_table() -> list[int]:
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        tab.append(c & 0xFFFFFFFF)
    return tab


_CRC32_TABLE = _make_table()


class ZipLegacyError(Exception):
    pass


def zipcrypto_decrypt(data: bytes, password: bytes, *, strip_header: bool = True) -> bytes:
    """Decrypt ZipCrypto (traditional PKWARE) `data`; drop the 12-byte header.

    The first 12 decrypted bytes are a random encryption header (a verifier);
    with `strip_header` the real plaintext (what follows) is returned.
    """
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def update(c: int):
        nonlocal k0, k1, k2
        k0 = _crc32_byte(k0, c)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)

    for c in password:
        update(c)

    out = bytearray()
    for cipher in data:
        temp = (k2 | 2) & 0xFFFF
        dec = cipher ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
        update(dec)
        out.append(dec)
    return bytes(out[12:]) if strip_header else bytes(out)


class _BitReader:
    """LSB-first bit reader (PKZIP bit order)."""
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.bitbuf = 0
        self.bitcnt = 0

    def bits(self, n: int) -> int:
        while self.bitcnt < n:
            b = self.data[self.pos] if self.pos < len(self.data) else 0
            self.pos += 1
            self.bitbuf |= b << self.bitcnt
            self.bitcnt += 8
        val = self.bitbuf & ((1 << n) - 1)
        self.bitbuf >>= n
        self.bitcnt -= n
        return val


_DLE = 0x90
_L_MASK = [0, 0x7F, 0x3F, 0x1F, 0x0F]
_D_SHIFT = [0, 7, 6, 5, 4]
_B_TABLE = [8, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]


def reduce_decompress(data: bytes, factor: int, out_size: int) -> bytes:
    """Un-Reduce `data` (PKZIP method 2-5; factor = method-1, 1..4) to out_size."""
    if not 1 <= factor <= 4:
        raise ZipLegacyError(f"reduce factor {factor} out of range (1..4)")
    br = _BitReader(data)
    followers: list[list[int]] = [[] for _ in range(256)]
    for x in range(255, -1, -1):
        n = br.bits(6)
        followers[x] = [br.bits(8) for _ in range(n)]

    out = bytearray()
    last_c = 0
    state = 0
    v = 0
    length = 0
    lmask = _L_MASK[factor]
    dshift = _D_SHIFT[factor]
    while len(out) < out_size:
        fset = followers[last_c]
        if not fset:
            c = br.bits(8)
        elif br.bits(1):
            c = br.bits(8)
        else:
            c = fset[br.bits(_B_TABLE[len(fset)])]
        last_c = c

        if state == 0:
            if c != _DLE:
                out.append(c)
            else:
                state = 1
        elif state == 1:
            if c != 0:
                v = c
                length = v & lmask
                state = 2 if length == lmask else 3
            else:
                out.append(_DLE)
                state = 0
        elif state == 2:
            length += c
            state = 3
        elif state == 3:
            dist = ((v >> dshift) << 8) + c + 1
            for _ in range(length + 3):
                out.append(out[-dist] if dist <= len(out) else 0)
            state = 0
    return bytes(out[:out_size])


_METHODS = {0: "stored", 1: "shrink", 2: "reduce-1", 3: "reduce-2",
            4: "reduce-3", 5: "reduce-4", 6: "implode", 8: "deflate"}


def extract_entries(data: bytes, password: bytes | None = None) -> list[dict]:
    """Decode every local file entry by scanning `PK\\x03\\x04` headers.

    Robust to a mangled/absent central directory (as CTF ZIPs use): we read the
    LOCAL headers directly. Handles stored / deflate (stdlib) and the legacy
    ZipCrypto + Reduce this module adds; other methods are reported, not decoded.
    Returns one dict per entry: {name, method, encrypted, usize, data?/error}.
    """
    out = []
    i = data.find(b"PK\x03\x04")
    while i >= 0:
        try:
            (_sig, _ver, flags, method, _mt, _md, _crc,
             csize, usize, nlen, elen) = struct.unpack_from("<IHHHHHIIIHH", data, i)
        except struct.error:
            break
        name = data[i + 30:i + 30 + nlen].decode("utf-8", "replace")
        body = data[i + 30 + nlen + elen: i + 30 + nlen + elen + csize]
        entry = {"name": name, "method": _METHODS.get(method, str(method)),
                 "encrypted": bool(flags & 1), "usize": usize, "csize": csize}
        try:
            raw = body
            if flags & 1:
                if password is None:
                    raise ZipLegacyError("entry is ZipCrypto-encrypted; password required")
                raw = zipcrypto_decrypt(raw, password)
            if method == 0:
                plain = raw[:usize]
            elif method == 8:
                plain = zlib.decompress(raw, -15)
            elif 2 <= method <= 5:
                plain = reduce_decompress(raw, method - 1, usize)
            else:
                raise ZipLegacyError(f"method {_METHODS.get(method, method)} not decoded")
            entry["data"] = plain
        except Exception as exc:  # noqa: BLE001 — report per-entry, keep scanning
            entry["error"] = str(exc)
        out.append(entry)
        nxt = data.find(b"PK\x03\x04", i + 4)
        i = nxt
    return out


def extract_file(path: str, password: bytes | None = None) -> list[dict]:
    """extract_entries over a file on disk (or any container holding a ZIP)."""
    return extract_entries(Path(path).read_bytes(), password)
