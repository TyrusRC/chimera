"""PyInstaller archive extraction — recover the embedded Python from a frozen EXE.

PyInstaller wraps a Python program plus its interpreter into one executable
by appending a **CArchive**: a cookie at EOF points at a table of contents,
and each entry is a (usually zlib-compressed) file — the bootstrap scripts,
the app's own modules, and a nested **PYZ** archive holding the marshalled
standard-library + third-party `.pyc`. Chimera wrapped native packers (UPX,
VMProtect) but had no path for this, the most common way malware and CTF
binaries ship Python — so a frozen EXE was a dead end. This gets the code
back out: the entry-point scripts, the app modules, and the PYZ contents,
each written as a loadable `.pyc` (header reconstructed) ready for `dis` or
a decompiler.

Pure-Python and read-only — it never executes the target. Based on the
well-known pyinstxtractor CArchive format; kept small and dependency-free.
"""
from __future__ import annotations

import logging
import marshal
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from chimera.unpacking.pymagic import (
    PYC_MAGIC as _PYC_MAGIC,
    pyc_header as _pyc_header,
    reconstruct_pyc as _reconstruct_pyc,
)

logger = logging.getLogger(__name__)

# The CArchive cookie magic PyInstaller writes near EOF (v2.1+ carries the
# python-lib name, so the cookie is 88 bytes: 8+4+4+4+4+64).
PYINST_MAGIC = b"MEI\014\013\012\013\016"
_COOKIE_FMT = "!8sIIII64s"          # magic, lengthOfPackage, toc, tocLen, pyver, pylib
_COOKIE_SIZE = struct.calcsize(_COOKIE_FMT)   # 88
_TOC_ENTRY_HDR = "!IIIIBc"          # entrySize, entryPos, cmprSize, uncmprSize, flag, type
_TOC_HDR_SIZE = struct.calcsize(_TOC_ENTRY_HDR)   # 18

@dataclass
class PyEntry:
    name: str
    type: str            # 's' script, 'm'/'M' module, 'z'/'Z' PYZ, 'b' binary, …
    size: int            # uncompressed size
    is_pyc: bool


@dataclass
class ExtractResult:
    ok: bool
    python_version: int | None = None       # e.g. 313 for 3.13
    out_dir: str | None = None
    entry_points: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    pyz_modules: list[str] = field(default_factory=list)
    entries: list[PyEntry] = field(default_factory=list)
    error: str | None = None
    note: str | None = None


def is_pyinstaller(data: bytes) -> bool:
    """True if the buffer carries a PyInstaller CArchive cookie."""
    return data.rfind(PYINST_MAGIC) != -1


def is_pyinstaller_file(path: str | Path, tail: int = 1 << 16) -> bool:
    """Cheaply check a file for the CArchive cookie by reading only its tail.

    The cookie sits at (or very near) EOF, so a frozen 17MB EXE can be
    detected without reading it all — this keeps the analyze hot path from
    misrouting a PyInstaller bundle into a full-binary Ghidra decompile.
    """
    try:
        with open(path, "rb") as fh:
            size = fh.seek(0, 2)
            fh.seek(max(0, size - tail))
            return PYINST_MAGIC in fh.read()
    except OSError:
        return False


def _safe_join(out_dir: Path, name: str) -> Path:
    """Join a TOC name under out_dir, refusing traversal out of the tree."""
    name = name.replace("\\", "/").lstrip("/")
    target = (out_dir / name).resolve()
    if not str(target).startswith(str(out_dir.resolve())):
        raise ValueError(f"path traversal in archive entry: {name!r}")
    return target


def _extract_pyz(pyz_data: bytes, out_dir: Path, pyver: int | None) -> list[str]:
    """Extract a nested PYZ archive's modules as .pyc. Returns module names.

    PYZ layout: b'PYZ\\0' magic, pyc-magic (u32), TOC position (u32), then a
    marshalled TOC {name: (typecode, offset, length)} and zlib blobs.
    """
    names: list[str] = []
    if pyz_data[:4] != b"PYZ\x00":
        return names
    try:
        toc_pos = struct.unpack("!I", pyz_data[8:12])[0]
        toc = marshal.loads(pyz_data[toc_pos:])
    except Exception as exc:  # malformed PYZ — extract nothing, don't crash
        logger.warning("PYZ TOC parse failed: %s", exc)
        return names
    items = toc.items() if isinstance(toc, dict) else toc
    pyz_out = out_dir / "PYZ_extracted"
    for entry in items:
        try:
            name, (_ispkg, offset, length) = entry
        except (ValueError, TypeError):
            continue
        name = name.decode() if isinstance(name, bytes) else name
        blob = pyz_data[offset:offset + length]
        try:
            body = zlib.decompress(blob)
        except zlib.error:
            body = blob
        rel = name.replace(".", "/") + ".pyc"
        try:
            dest = _safe_join(pyz_out, rel)
        except ValueError:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(_reconstruct_pyc(body, pyver))
        names.append(name)
    return names


def extract_pyinstaller(path: str | Path, out_dir: str | Path) -> ExtractResult:
    """Extract a PyInstaller EXE's embedded Python into `out_dir`.

    Returns an ExtractResult listing entry-point scripts, app modules, and
    PYZ modules. Read-only: the target is never executed.
    """
    path = Path(path)
    out_dir = Path(out_dir)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return ExtractResult(ok=False, error=f"cannot read {path}: {exc}")

    cookie_pos = data.rfind(PYINST_MAGIC)
    if cookie_pos == -1:
        return ExtractResult(ok=False, error="not a PyInstaller archive (no CArchive cookie)")

    magic, length_of_pkg, toc, toc_len, pyver, pylib = struct.unpack(
        _COOKIE_FMT, data[cookie_pos:cookie_pos + _COOKIE_SIZE])

    tail = len(data) - cookie_pos - _COOKIE_SIZE
    overlay_size = length_of_pkg + tail
    overlay_pos = len(data) - overlay_size
    toc_pos = overlay_pos + toc

    out_dir.mkdir(parents=True, exist_ok=True)
    result = ExtractResult(ok=True, python_version=pyver, out_dir=str(out_dir))
    if pyver not in _PYC_MAGIC:
        result.note = (f"python {pyver} pyc-magic unknown; .pyc headers zeroed "
                       "(raw marshal still extracted)")

    pos = toc_pos
    end = toc_pos + toc_len
    while pos < end:
        (entry_size,) = struct.unpack("!I", data[pos:pos + 4])
        if entry_size < _TOC_HDR_SIZE:
            break
        (_esize, entry_pos, cmpr_size, uncmpr_size, flag, type_b) = struct.unpack(
            _TOC_ENTRY_HDR, data[pos:pos + _TOC_HDR_SIZE])
        name = data[pos + _TOC_HDR_SIZE:pos + entry_size].rstrip(b"\x00").decode(
            "latin-1") or f"unnamed_{entry_pos}"
        etype = type_b.decode("latin-1")
        pos += entry_size

        blob = data[overlay_pos + entry_pos:overlay_pos + entry_pos + cmpr_size]
        if flag:
            try:
                body = zlib.decompress(blob)
            except zlib.error:
                body = blob
        else:
            body = blob

        is_pyc = etype in ("s", "m", "M")
        result.entries.append(PyEntry(name=name, type=etype, size=uncmpr_size, is_pyc=is_pyc))

        if etype in ("z", "Z"):                    # nested PYZ archive
            result.pyz_modules += _extract_pyz(body, out_dir, pyver)
            continue

        try:
            dest = _safe_join(out_dir, name)
        except ValueError:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if is_pyc:
            dest = dest.with_suffix(".pyc")
            dest.write_bytes(_reconstruct_pyc(body, pyver))
            (result.entry_points if etype == "s" else result.modules).append(name)
        else:
            dest.write_bytes(body)

    return result
