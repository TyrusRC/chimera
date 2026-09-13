"""Recover the embedded JavaScript from a Node.js compiled executable.

Three tools ship a whole Node app as one native binary by appending/embedding
the JS bundle in the executable:

* **nexe** — appends `[bundle][resources]<nexe~~sentinel>` plus a 16-byte
  footer of two little-endian float64 sizes (content, resources). The bundle
  is the app's JS, stored plain (or gzip'd on old versions).
* **Node SEA** (Single Executable Applications, official since Node 20) —
  postject injects a serialized blob (magic ``0x143DB6DE``, a uint32 flags,
  then a size-prefixed main-script string) as a resource/section, with a
  ``NODE_SEA_BLOB`` name and a ``NODE_SEA_FUSE_…`` sentinel in the binary.
* **pkg** (vercel/pkg) — embeds a virtual filesystem + a `pkg/prelude`
  bootstrap; the payload can be V8 bytecode, not plain JS.

Chimera wrapped native packers (UPX) and PyInstaller but had no path for a
Node compiled binary, so a 50MB nexe/SEA `.exe` was a dead end (analyze would
try to Ghidra-decompile the whole node runtime). This carves the JS back out
so it can go straight to `js_deobf`. nexe and SEA are extracted; pkg is
detected with guidance (its VFS/bytecode payload is target-specific, so —
like the VM-protector unpackers — we surface the approach rather than ship a
subtly-wrong auto-extractor).

Pure-Python, read-only — it never executes the target and never reaches the
network. Format-agnostic: it scans the raw bytes, so it works whether the host
executable is a PE, ELF, or Mach-O.
"""
from __future__ import annotations

import logging
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# nexe appends this sentinel, then two float64 LE sizes (content, resources).
NEXE_SENTINEL = b"<nexe~~sentinel>"
_NEXE_FOOTER = struct.Struct("<dd")   # contentSize, resourceSize (doubles)

# Node SEA serialized-blob magic (src/node_sea.cc), little-endian on disk.
SEA_MAGIC = 0x143DB6DE
_SEA_MAGIC_LE = struct.pack("<I", SEA_MAGIC)
# SeaFlags bits we care about; kUseSnapshot means the payload is a V8 snapshot,
# not JS source.
_SEA_FLAG_USE_SNAPSHOT = 1 << 1
# postject marks the injected resource with this name and drops a fuse token.
_SEA_MARKERS = (b"NODE_SEA_BLOB", b"NODE_SEA_FUSE_")

# pkg leaves its bootstrap path in the embedded VFS even after patching.
_PKG_MARKERS = (b"pkg/prelude/bootstrap.js", b"pkg/prelude", b"PAYLOAD_POSITION")


@dataclass
class NodeExtractResult:
    ok: bool                       # did we write a JS payload out?
    kind: str | None = None        # "nexe" | "sea" | "pkg" | None
    out_file: str | None = None
    js_size: int | None = None
    resource_size: int | None = None
    sea_flags: int | None = None
    signals: list[str] = field(default_factory=list)
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "kind": self.kind, "out_file": self.out_file,
            "js_size": self.js_size, "resource_size": self.resource_size,
            "sea_flags": self.sea_flags, "signals": self.signals,
            "note": self.note, "error": self.error,
        }


def detect_node_binary(data: bytes) -> str | None:
    """Return "nexe" | "sea" | "pkg" for a Node compiled binary, else None."""
    if NEXE_SENTINEL in data:
        return "nexe"
    if any(m in data for m in _SEA_MARKERS):
        return "sea"
    if any(m in data for m in _PKG_MARKERS):
        return "pkg"
    return None


def detect_node_binary_file(path: str | Path) -> str | None:
    try:
        return detect_node_binary(Path(path).read_bytes())
    except OSError:
        return None


def _maybe_inflate(blob: bytes) -> bytes:
    """nexe stores the bundle plain today, gzip on old versions — inflate if so."""
    if blob[:2] == b"\x1f\x8b":            # gzip
        try:
            return zlib.decompress(blob, wbits=16 + zlib.MAX_WBITS)
        except zlib.error:
            pass
    if blob[:2] == b"\x78":                # zlib
        try:
            return zlib.decompress(blob)
        except zlib.error:
            pass
    return blob


def extract_nexe(data: bytes) -> tuple[bytes, int]:
    """Carve the JS bundle from a nexe binary. Returns (js_bytes, resource_size).

    Layout: ``[node][content][resources]<nexe~~sentinel>[f64 content][f64 res]``.
    The sentinel is found from the end (rfind) to tolerate trailing padding.
    Raises ValueError on a malformed/absent footer.
    """
    pos = data.rfind(NEXE_SENTINEL)
    if pos == -1:
        raise ValueError("no nexe sentinel")
    foot_off = pos + len(NEXE_SENTINEL)
    if foot_off + _NEXE_FOOTER.size > len(data):
        raise ValueError("truncated nexe footer")
    content_size, resource_size = _NEXE_FOOTER.unpack_from(data, foot_off)
    content_size, resource_size = int(content_size), int(resource_size)
    content_start = pos - resource_size - content_size
    if content_size <= 0 or content_start < 0 or content_start + content_size > pos:
        raise ValueError(
            f"implausible nexe sizes: content={content_size} resource={resource_size}")
    content = data[content_start:content_start + content_size]
    return _maybe_inflate(content), resource_size


def extract_sea(data: bytes) -> tuple[bytes, int]:
    """Carve the main script from a Node SEA blob. Returns (code_bytes, flags).

    Blob: ``magic(u32) flags(u32) len(size_t) code[len] …``. size_t is 8 bytes
    on the 64-bit builds that produce SEAs; falls back to 4 for a 32-bit host.
    Scans every magic occurrence and takes the first with a sane length, so a
    stray constant elsewhere in the node runtime doesn't derail it.
    """
    start = 0
    while True:
        mpos = data.find(_SEA_MAGIC_LE, start)
        if mpos == -1:
            raise ValueError("no SEA blob magic with a valid length")
        start = mpos + 4
        if mpos + 8 > len(data):
            continue
        flags = struct.unpack_from("<I", data, mpos + 4)[0]
        for width, fmt in ((8, "<Q"), (4, "<I")):
            hdr_end = mpos + 8 + width
            if hdr_end > len(data):
                continue
            clen = struct.unpack_from(fmt, data, mpos + 8)[0]
            if 0 < clen <= len(data) - hdr_end:
                return data[hdr_end:hdr_end + clen], flags


def extract_node_js(path: str | Path, out_dir: str | Path | None = None) -> NodeExtractResult:
    """Detect a Node compiled binary and write its embedded JS to `out_dir`.

    Read-only; the target is never executed. Hand the recovered `.js` to
    `js_deobf` for the greppable source.
    """
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return NodeExtractResult(ok=False, error=f"cannot read {path}: {exc}")

    kind = detect_node_binary(data)
    if kind is None:
        return NodeExtractResult(ok=False, error="not a Node compiled binary "
                                 "(no nexe / SEA / pkg marker found)")

    out_root = Path(out_dir) if out_dir else path.with_name(path.stem + "_node")
    signals = [kind]

    if kind == "pkg":
        return NodeExtractResult(
            ok=False, kind="pkg", signals=signals,
            note="vercel/pkg binary: payload is a virtual filesystem and may be "
                 "V8 bytecode (--target with -C, not plain JS). Use pkg-unpacker "
                 "/ the `pkg/prelude` VFS offsets, then js_deobf the recovered .js.")

    try:
        if kind == "nexe":
            js, resource_size = extract_nexe(data)
            flags = None
            note = None
        else:  # sea
            js, flags = extract_sea(data)
            resource_size = None
            note = None
            if flags & _SEA_FLAG_USE_SNAPSHOT:
                note = ("SEA useSnapshot flag set — payload is a V8 startup "
                        "snapshot, not JS source; written raw.")
    except ValueError as exc:
        return NodeExtractResult(ok=False, kind=kind, signals=signals,
                                 error=f"{kind} extraction failed: {exc}")

    out_root.mkdir(parents=True, exist_ok=True)
    is_js = not (kind == "sea" and flags and (flags & _SEA_FLAG_USE_SNAPSHOT))
    out_file = out_root / (f"{path.stem}.js" if is_js else f"{path.stem}.snapshot.bin")
    out_file.write_bytes(js)

    return NodeExtractResult(
        ok=True, kind=kind, out_file=str(out_file), js_size=len(js),
        resource_size=resource_size, sea_flags=flags, signals=signals, note=note)
