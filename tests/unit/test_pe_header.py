"""Unit tests for the PE header parser."""
import struct
from pathlib import Path

import pytest

pefile = pytest.importorskip("pefile")

from chimera.parsers.pe_header import (
    PEHeaderInfo, PESection, parse_pe, _shannon_entropy,
)


def _build_minimal_pe64(path: Path, *, is_dll: bool = True, is_dotnet: bool = False) -> Path:
    """Build a tiny but pefile-parseable PE32+ file.

    Layout:
      0x000  DOS header (MZ + e_lfanew at 0x3C → 0x80)
      0x080  PE signature
      0x084  IMAGE_FILE_HEADER (20 bytes)
      0x098  IMAGE_OPTIONAL_HEADER (240 bytes for PE32+)
      0x188  Section Header (40 bytes per section, 1 section)
      0x200  Section data (executable code stub)
    """
    BUF_SIZE = 0x800
    SEC_VA = 0x1000
    SEC_RAW_OFF = 0x200
    SEC_RAW_SIZE = 0x200
    OPT_HDR_SIZE = 240  # PE32+ optional header

    buf = bytearray(BUF_SIZE)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)

    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER: Machine=x86_64, NumSec=1, TimeDateStamp=0, SymbolPtr=0,
    # NumSym=0, SizeOfOptionalHeader=240, Characteristics=DLL bit if requested
    chars = 0x2000 if is_dll else 0x0
    struct.pack_into("<HHIIIHH", buf, pe_off + 4,
                     0x8664, 1, 0, 0, 0, OPT_HDR_SIZE, chars)
    opt_off = pe_off + 24
    # OPTIONAL_HEADER: pack the fields pefile actually reads
    # Magic=0x20b, MajorLink=0, MinorLink=0, SizeOfCode=SEC_RAW_SIZE,
    # SizeOfInitializedData=0, SizeOfUninitializedData=0,
    # AddressOfEntryPoint=SEC_VA, BaseOfCode=SEC_VA
    struct.pack_into("<HBBIIII", buf, opt_off,
                     0x20b, 0, 0, SEC_RAW_SIZE, 0, 0, SEC_VA)
    # Skip BaseOfCode (4) and ImageBase (8)
    struct.pack_into("<IQ", buf, opt_off + 20, SEC_VA, 0x140000000)
    # SectionAlignment=0x1000, FileAlignment=0x200
    struct.pack_into("<II", buf, opt_off + 32, 0x1000, 0x200)
    # MajorOSVer..MinorImageVer (8 bytes of versions): all zero
    struct.pack_into("<HHHHHH", buf, opt_off + 40, 6, 0, 0, 0, 6, 0)
    # Win32VersionValue=0, SizeOfImage=0x2000, SizeOfHeaders=0x200, CheckSum=0
    struct.pack_into("<IIII", buf, opt_off + 52, 0, 0x2000, 0x200, 0)
    # Subsystem=3 (Console), DllCharacteristics=0
    struct.pack_into("<HH", buf, opt_off + 68, 3, 0)
    # SizeOfStack/HeapReserve/Commit (4 x uint64) all zero
    # NumberOfRvaAndSizes=16 at opt_off + 108 (PE32+ specific)
    struct.pack_into("<I", buf, opt_off + 108, 16)
    # 16 DataDirectory entries (8 bytes each): all zero unless we want CLR
    if is_dotnet:
        # DataDirectory[14] = CLR header
        clr_off = opt_off + 112 + 14 * 8
        struct.pack_into("<II", buf, clr_off, 0x2000, 0x48)

    # Section header at opt_off + 240 = pe_off + 264 = 0x80 + 264 = 0x188
    sec_off = opt_off + 240
    name = b".text\x00\x00\x00"
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off,
                     name, SEC_RAW_SIZE, SEC_VA, SEC_RAW_SIZE, SEC_RAW_OFF,
                     0, 0, 0, 0, 0x60000020)  # IMAGE_SCN_CNT_CODE | EXEC | READ

    # Section data: just zeros at SEC_RAW_OFF (already in buf)
    path.write_bytes(bytes(buf))
    return path


def test_shannon_entropy_uniform_returns_8():
    data = bytes(range(256))
    assert abs(_shannon_entropy(data) - 8.0) < 0.001


def test_shannon_entropy_constant_returns_0():
    assert _shannon_entropy(b"\x00" * 1024) == 0.0


def test_parse_pe_minimal_dll(tmp_path):
    p = _build_minimal_pe64(tmp_path / "x.dll", is_dll=True)
    info = parse_pe(p)
    assert info.machine == "x86_64"
    assert info.is_dll is True
    assert info.is_dotnet is False
    assert info.pe_class == "PE32+"
    assert len(info.sections) == 1
    assert info.sections[0].name == ".text"
    assert info.sections[0].is_executable is True
    assert info.imports == []
    assert info.exports == []
    assert info.has_authenticode_signature is False


def test_parse_pe_dotnet_flag(tmp_path):
    p = _build_minimal_pe64(tmp_path / "x.dll", is_dotnet=True)
    info = parse_pe(p)
    assert info.is_dotnet is True
