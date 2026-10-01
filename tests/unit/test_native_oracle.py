"""Tests for the native-oracle primitive (dynamic/native_oracle.py)."""
from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from chimera.dynamic import native_oracle as no


def _min_pe() -> bytes:
    """A minimal valid PE32+ with one section, for header parsing."""
    image_base = 0x140000000
    e_lfanew = 0x80
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    struct.pack_into("<H", data, coff + 0, 0x8664)      # machine x64
    struct.pack_into("<H", data, coff + 2, 1)           # nsections
    opt_size = 0xF0
    struct.pack_into("<H", data, coff + 16, opt_size)   # SizeOfOptionalHeader
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)            # PE32+
    struct.pack_into("<Q", data, opt + 24, image_base)  # ImageBase
    struct.pack_into("<I", data, opt + 56, 0x2000)      # SizeOfImage
    struct.pack_into("<I", data, opt + 60, 0x400)       # SizeOfHeaders
    sh = opt + opt_size
    data[sh:sh + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sh + 8, 0x200, 0x1000, 0x200, 0x400)  # vsize,vaddr,rawsize,rawptr
    return bytes(data)


def test_pe_segments_parses_base_and_sections():
    base, span, segs = no.pe_segments(_min_pe())
    assert base == 0x140000000
    assert span == 0x2000
    # first segment is the headers page; then the .text section
    assert no.Segment(0x140000000, 0, 0x400) == segs[0]
    text = [s for s in segs if s.va == 0x140001000]
    assert text and text[0].file_off == 0x400 and text[0].size == 0x200


def test_pe_segments_rejects_non_pe():
    with pytest.raises(ValueError):
        no.pe_segments(b"not a pe at all")


def test_generate_harness_contains_map_copies_and_body():
    segs = [no.Segment(0x140000000, 0, 0x400), no.Segment(0x140001000, 0x400, 0x200)]
    src = no.generate_harness(0x140000000, 0x2000, segs,
                              body="  puts(\"HELLO\");", preamble="static int K=7;")
    assert "MAP_FIXED" in src and "0x140000000" in src.lower()
    assert "memcpy((uint8_t*)IMG + 0x1000, fb + 0x400, 0x200);" in src
    assert "puts(\"HELLO\");" in src and "static int K=7;" in src
    assert "__attribute__((ms_abi))" in src           # WIN64 helper available


@pytest.mark.skipif(not no.gcc_available(), reason="gcc required")
def test_run_native_oracle_end_to_end_elf(tmp_path):
    """Compile a non-PIE ELF with a known leaf function, then map+call it via
    the native oracle and check the returned value — proves the whole pipeline."""
    if not shutil.which("bwrap"):
        pytest.skip("bwrap required for confined run")
    src = tmp_path / "target.c"
    src.write_text("int chimera_add7(int x){return x+7;}\n"
                   "int main(void){return chimera_add7(0);}\n")
    target = tmp_path / "target"
    rc = subprocess.run(["gcc", "-no-pie", "-fno-pic", "-O0", "-o", str(target), str(src)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip(f"cannot build non-PIE target: {rc.stderr}")
    nm = subprocess.run(["nm", str(target)], capture_output=True, text=True)
    addr = None
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "chimera_add7":
            addr = int(parts[0], 16)
    assert addr, "could not find chimera_add7 address"
    body = (f"  typedef int (SYSV *f)(int);\n"
            f"  printf(\"%d\\n\", ((f){addr:#x})(35));")
    res = no.run_native_oracle(str(target), body, timeout=30)
    assert res["compiled"] and res["ran"], res
    assert res["stdout"].strip() == "42", res
