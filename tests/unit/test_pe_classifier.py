"""Unit tests for the PE magic-byte classifier."""
import struct
from pathlib import Path

import pytest

from chimera.model.binary import BinaryFormat, _classify_pe


def _build_pe(magic_optional: int, clr_va: int = 0, clr_size: int = 0,
              pe_off: int = 0x80) -> bytes:
    """Build a minimal valid PE byte buffer.

    magic_optional: 0x10b for PE32, 0x20b for PE32+
    clr_va, clr_size: CLR data dir entry. Non-zero => .NET.
    """
    buf = bytearray(b"\x00" * 0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)
    # PE signature
    buf[pe_off:pe_off+4] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER (20 bytes after signature)
    # Machine=0x8664 (AMD64) for PE32+, 0x14c (i386) for PE32
    machine = 0x8664 if magic_optional == 0x20b else 0x14c
    struct.pack_into("<HHIIIHH", buf, pe_off + 4,
                     machine, 1, 0, 0, 0, 0, 0)  # NumSec=1, SizeOfOptHdr=0 (we'll fill below)
    # OptionalHeader.Magic at pe_off+24
    struct.pack_into("<H", buf, pe_off + 24, magic_optional)
    # CLR data dir at offset depending on PE32 vs PE32+
    clr_off = pe_off + 24 + (224 if magic_optional == 0x20b else 208)
    struct.pack_into("<II", buf, clr_off, clr_va, clr_size)
    return bytes(buf)


def test_classify_pe32(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(_build_pe(0x10b))
    assert _classify_pe(p) == BinaryFormat.PE32


def test_classify_pe64(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(_build_pe(0x20b))
    assert _classify_pe(p) == BinaryFormat.PE64


def test_classify_dotnet_pe32(tmp_path):
    p = tmp_path / "x.dll"
    p.write_bytes(_build_pe(0x10b, clr_va=0x2000, clr_size=0x48))
    assert _classify_pe(p) == BinaryFormat.DOTNET_PE


def test_classify_dotnet_pe64(tmp_path):
    p = tmp_path / "x.dll"
    p.write_bytes(_build_pe(0x20b, clr_va=0x2000, clr_size=0x48))
    assert _classify_pe(p) == BinaryFormat.DOTNET_PE


def test_classify_pe_falls_back_on_malformed_no_pe_signature(tmp_path):
    """When MZ is present but the e_lfanew offset doesn't point to PE\\0\\0,
    return PE32 as a stable default rather than raising."""
    p = tmp_path / "x.exe"
    buf = bytearray(b"\x00" * 0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    # Leave the would-be PE signature region as zeros (no "PE\0\0")
    p.write_bytes(bytes(buf))
    assert _classify_pe(p) == BinaryFormat.PE32


def test_classify_pe_falls_back_on_truncated_file(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\x00" * 4)  # too short
    assert _classify_pe(p) == BinaryFormat.PE32


def test_detect_format_routes_mz_to_classify_pe(tmp_path):
    from chimera.model.binary import _detect_format
    p = tmp_path / "y.exe"
    p.write_bytes(_build_pe(0x20b))
    assert _detect_format(p) == BinaryFormat.PE64


def test_detect_format_routes_dotnet_dll(tmp_path):
    from chimera.model.binary import _detect_format
    p = tmp_path / "y.dll"
    p.write_bytes(_build_pe(0x20b, clr_va=0x2000, clr_size=0x48))
    assert _detect_format(p) == BinaryFormat.DOTNET_PE
