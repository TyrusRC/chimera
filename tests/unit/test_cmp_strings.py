"""Recovering a hidden string from a byte-comparison cascade (Magic 8 Ball)."""
from __future__ import annotations

import struct

from chimera.parsers.cmp_strings import (
    _last_immediate,
    _store_immediate,
    recover_compare_string,
    recover_data_bytes,
)


def _elf64_one_load(load_vaddr=0x400000, load_size=0x1000) -> bytearray:
    ehsize, phentsize = 64, 56
    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr += struct.pack("<HH", 2, 0x3E) + struct.pack("<I", 1)         # ET_EXEC, EM_X86_64
    ehdr += struct.pack("<QQQ", load_vaddr, ehsize, 0) + struct.pack("<I", 0)
    ehdr += struct.pack("<H", ehsize) + struct.pack("<HH", phentsize, 1) + struct.pack("<HHH", 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, load_vaddr, load_vaddr, load_size, load_size, 0x1000)
    return bytearray(ehdr + phdr + b"\x00" * (0x200 - (ehsize + phentsize)) + b"\x00" * load_size)


# "LLURULDUL" as an unrolled cascade at VA 0x400500, each char compare preceded
# by a `cmp eax, 0xf` length-guard (imm 0xf is non-printable → must be filtered).
_CASCADE_HEX = ("83f80f803b4c83f80f807b014c83f80f807b025583f80f807b035283f80f807b045583"
                "f80f807b054c83f80f807b064483f80f807b075583f80f807b084c")


def _plant(tmp_path):
    raw = _elf64_one_load()
    code = bytes.fromhex(_CASCADE_HEX)
    raw[0x500:0x500 + len(code)] = code       # file offset 0x500 == VA 0x400500
    f = tmp_path / "m8.elf"
    f.write_bytes(bytes(raw))
    return f


def test_recovers_cmp_cascade_string(tmp_path):
    f = _plant(tmp_path)
    r = recover_compare_string(str(f), 0x400500)
    assert r["arch"] == "x86_64"
    assert r["candidates"], "no cascade recovered"
    assert r["candidates"][0]["string"] == "LLURULDUL"   # length-guards filtered out
    assert r["candidates"][0]["count"] == 9


def test_last_immediate_ignores_memory_displacement():
    assert _last_immediate("al, 0x55") == 0x55           # real compared byte
    assert _last_immediate("eax, 0xf") == 0xf            # length check (filtered later)
    assert _last_immediate("byte ptr [eax + 0x4c], bl") is None  # displacement, not a value
    assert _last_immediate("") is None


def test_min_run_filters_short_cascades(tmp_path):
    f = _plant(tmp_path)
    r = recover_compare_string(str(f), 0x400500, min_run=20)
    assert r["candidates"] == []                          # 9 < 20, nothing qualifies


def test_unparseable_file_reports_error(tmp_path):
    junk = tmp_path / "x.bin"
    junk.write_bytes(b"not a binary" * 4)
    r = recover_compare_string(str(junk), 0x1000)
    assert r["available"] and "error" in r


# --- immediate-store byte-array recovery (darn_mice) --------------------------

# 2 dword stores + 2 byte stores at VA 0x400500 → data [0x50,0x5e,0x5e,0xa3,
# 0x4f,0x5b,0x51,0x5e,0x6b,0x7f]; proves dword immediates split little-endian.
_STORE_HEX = "c703505e5ea3c743044f5b515ec643086bc643097f"
_STORE_DATA = [0x50, 0x5e, 0x5e, 0xA3, 0x4F, 0x5B, 0x51, 0x5E, 0x6B, 0x7F]


def _plant_stores(tmp_path):
    raw = _elf64_one_load()
    code = bytes.fromhex(_STORE_HEX)
    raw[0x500:0x500 + len(code)] = code
    f = tmp_path / "dm.elf"
    f.write_bytes(bytes(raw))
    return f


def test_recover_data_bytes_splits_dword_stores_little_endian(tmp_path):
    f = _plant_stores(tmp_path)
    r = recover_data_bytes(str(f), 0x400500)
    assert r["byte_count"] == 10
    assert list(bytes.fromhex(r["hex"])) == _STORE_DATA   # dword LE order intact


def test_recover_data_bytes_inverts_additive_gadget(tmp_path):
    f = _plant_stores(tmp_path)
    r = recover_data_bytes(str(f), 0x400500, gadget_target=0xC3)
    # input[i] = (0xC3 - data[i]) & 0xff — the darn_mice "make every byte ret" trick
    assert r["derived_input_ascii"] == "see threXD"


def test_store_immediate_distinguishes_dword_from_word(tmp_path):
    # regression: "word ptr" is a substring of "dword ptr" — must not match width 2
    assert _store_immediate("dword ptr [rbx], 0xa35e5e50") == (4, 0xA35E5E50)
    assert _store_immediate("word ptr [rbx], 0x4142") == (2, 0x4142)
    assert _store_immediate("byte ptr [rbx + 8], 0x6b") == (1, 0x6B)
    assert _store_immediate("eax, 0x50") is None          # mov reg,imm is not a store
    assert _store_immediate("byte ptr [rbx], al") is None  # store of a register, no imm
