"""Robustness tests for the Mach-O parser on malformed input."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from chimera.parsers.macho_objc import ObjCMetadata, parse_objc_metadata


def _write_macho(path: Path, *, ncmds: int, cmdsize: int, extra: bytes = b"") -> None:
    """Write a minimal 64-bit Mach-O header that the load-command walker will read.

    Lays out one stub load-command (LC_SEGMENT_64) with the supplied (possibly
    malformed) cmdsize, then pads to a real-on-disk cmdsize-worth of bytes only
    when cmdsize is small enough to fit in memory cheaply. For oversized
    cmdsize, the on-disk body is intentionally smaller than the cmdsize field
    so the parser is forced to either bounds-check or walk past EOF.
    """
    MH_MAGIC_64 = 0xFEEDFACF
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        0x01000007,  # cputype: x86_64
        3,           # cpusubtype
        2,           # filetype: MH_EXECUTE
        ncmds,
        ncmds * cmdsize if cmdsize else 0,  # sizeofcmds
        0,           # flags
        0,           # reserved
    )
    # Minimum on-disk body: just the 8-byte (cmd, cmdsize) pair, repeated.
    body = struct.pack("<II", 0x19, cmdsize)
    path.write_bytes(header + body * ncmds + extra)


def test_zero_cmdsize_does_not_infinite_loop(tmp_path):
    """cmdsize=0 must not cause the walker to spin or re-read the same offset
    indefinitely; an empty/partial result is acceptable, an exception is not."""
    p = tmp_path / "bad_zero.macho"
    _write_macho(p, ncmds=3, cmdsize=0)
    result = parse_objc_metadata(p)
    assert isinstance(result, ObjCMetadata)
    assert result.classes == []
    assert result.categories == []
    assert result.protocols == []


def test_oversized_cmdsize_is_rejected(tmp_path):
    """cmdsize that walks past EOF must not raise struct.error / IndexError.

    With ncmds=2, the walker advances cur by the oversized cmdsize after the
    first iteration and must then attempt to read at an out-of-bounds offset.
    A bounds-checked walker bails out cleanly.
    """
    p = tmp_path / "bad_overflow.macho"
    _write_macho(p, ncmds=2, cmdsize=10**9)  # 1 GB cmdsize on a ~50-byte file
    result = parse_objc_metadata(p)
    assert isinstance(result, ObjCMetadata)
    assert result.classes == []
