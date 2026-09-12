"""Recovering a hidden string from a byte-comparison cascade (Magic 8 Ball)."""
from __future__ import annotations

import struct

from chimera.parsers.cmp_strings import _last_immediate, recover_compare_string


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
