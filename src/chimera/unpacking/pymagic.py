"""Python bytecode magic numbers — shared pyc header logic.

CPython stamps a compiled module with a 2-byte magic that changes every
time the bytecode format changes, so the interpreter refuses a `.pyc` built
for a different version. The extractors here need it from two directions:
to *reconstruct* a loadable header for a bare marshalled code object (the
PyInstaller path strips it), and to *detect* which version a blob was
compiled for so a cross-version disassembler picks the right opcode table.

Kept in one small module because both `pyinstaller` and `pybytecode` rely
on it — duplicating the table would let the two drift out of sync.
"""
from __future__ import annotations

import struct

# pyc magic numbers (the u16 little-endian value, before the trailing \r\n)
# keyed by the compact CPython version int (3.12 -> 312). Extended as new
# releases land; an unknown version reconstructs a zeroed magic (the raw
# marshal still loads, only the header is a placeholder).
PYC_MAGIC: dict[int, int] = {
    311: 3495, 312: 3531, 313: 3571, 314: 3608,
    38: 3413, 39: 3425, 310: 3439,
}

#: value -> version, for going from a magic back to a version int.
_MAGIC_TO_VERSION: dict[int, int] = {v: k for k, v in PYC_MAGIC.items()}


def pyc_header(pyver: int | None) -> bytes:
    """A 16-byte pyc header for `pyver` (flags=0, mtime=0, size=0)."""
    magic_int = PYC_MAGIC.get(pyver or 0, 0)
    magic = struct.pack("<H", magic_int) + b"\r\n"
    return magic + b"\x00" * 12


def reconstruct_pyc(body: bytes, pyver: int | None) -> bytes:
    """Prepend a pyc header if a bare marshalled code object lacks one.

    A raw marshalled code object starts with the 'c' / 0xE3 type byte in
    CPython; a real pyc starts with the magic. Heuristic: if the first two
    bytes already match a known magic, assume it is headered and keep it;
    otherwise prepend one so a decompiler / `dis` will load it.
    """
    if len(body) >= 2:
        first = struct.unpack("<H", body[:2])[0]
        if first in PYC_MAGIC.values():
            return body
    return pyc_header(pyver) + body


def detect_pyc_version(code_or_magic: bytes | int | None) -> int | None:
    """Return the compact version int (e.g. 312) for a pyc magic, else None.

    Accepts either the raw magic as an int, or a bytes buffer whose first
    two bytes are the little-endian magic (a full pyc, or just its header).
    """
    if isinstance(code_or_magic, int):
        return _MAGIC_TO_VERSION.get(code_or_magic)
    if isinstance(code_or_magic, (bytes, bytearray)) and len(code_or_magic) >= 2:
        magic = struct.unpack("<H", bytes(code_or_magic[:2]))[0]
        return _MAGIC_TO_VERSION.get(magic)
    return None
