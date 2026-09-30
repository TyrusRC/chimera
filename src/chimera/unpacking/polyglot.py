"""Scan a file for embedded formats at ANY offset — polyglot triage.

A polyglot / carved-container CTF file (FLARE-ON's FlareOn13.doc was PDF + ZIP +
Mach-O + VHD + EICAR in one file) hides real payloads at non-zero offsets that a
first-format parser never reaches. chimera has per-format carvers (uefi, pdf,
nodejs, …) but no one pass that finds every embedded format. This scans for known
magics at every offset, computes a size where the format lets it, and carves any
region out. Read-only; a bare `carve` writes exactly the requested byte range.
"""
from __future__ import annotations

import struct
from pathlib import Path

# (name, magic). Magic may occur at any offset; some are disambiguated below.
_SIGS: list[tuple[str, bytes]] = [
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("macho-fat", b"\xca\xfe\xba\xbe"),        # NB: also a Java .class magic
    ("macho-fat-le", b"\xbe\xba\xfe\xca"),
    ("macho64", b"\xcf\xfa\xed\xfe"),
    ("macho64-be", b"\xfe\xed\xfa\xcf"),
    ("macho32", b"\xce\xfa\xed\xfe"),
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("zip-eocd", b"PK\x05\x06"),
    ("gzip", b"\x1f\x8b\x08"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("rar", b"Rar!\x1a\x07"),
    ("vhd", b"conectix"),
    ("iso9660/udf", b"CD001"),
    ("eicar", b"X5O!P%@AP"),
]

_MAX_PER_FORMAT = 16


def _macho_fat_slices(data: bytes, off: int) -> list[dict]:
    """Parse a fat Mach-O header at `off` → its arch slices (offset/size)."""
    try:
        _magic, nfat = struct.unpack_from(">II", data, off)
        slices = []
        for k in range(min(nfat, 64)):
            base = off + 8 + k * 20
            cput, csub, soff, ssize, _align = struct.unpack_from(">IIIII", data, base)
            slices.append({"cputype": cput, "subtype": csub, "offset": soff, "size": ssize})
        return slices
    except struct.error:
        return []


def _size(name: str, data: bytes, off: int) -> int | None:
    if name == "macho-fat":
        slices = _macho_fat_slices(data, off)
        if slices:
            return max(s["offset"] + s["size"] for s in slices)
    if name == "pdf":
        end = data.rfind(b"%%EOF", off)
        return (end + 5 - off) if end > off else None
    if name == "zip-eocd":
        return 22  # minimal EOCD; comment length ignored for triage
    return None


def _keep_pe(data: bytes, off: int) -> bool:
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
        return data[off + e_lfanew: off + e_lfanew + 4] == b"PE\x00\x00"
    except (struct.error, IndexError):
        return False


def scan(path: str) -> list[dict]:
    data = Path(path).read_bytes()
    hits: list[dict] = []
    for name, magic in _SIGS:
        start = 0
        count = 0
        while count < _MAX_PER_FORMAT:
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            count += 1
            if name == "pe" and not _keep_pe(data, i):
                continue
            hit = {"format": name, "offset": i, "size": _size(name, data, i)}
            if name == "macho-fat":
                hit["slices"] = _macho_fat_slices(data, i)
            hits.append(hit)
    hits.sort(key=lambda h: h["offset"])
    return hits


def carve(path: str, offset: int, out_path: str, size: int | None = None) -> int:
    """Write data[offset:offset+size] (or offset→EOF) to out_path; return bytes written."""
    data = Path(path).read_bytes()
    blob = data[offset: offset + size] if size is not None else data[offset:]
    Path(out_path).write_bytes(blob)
    return len(blob)
