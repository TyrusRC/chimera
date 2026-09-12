"""Assembler (keystone) + arch auto-detection + patch_asm glue.

The assembler is what lets a patch be written as source instead of hand-encoded
hex; the arch sniff is what stops ARM source being silently assembled as x86.
Encoding assertions skip cleanly when keystone (the `patch` extra) isn't present.
"""
from __future__ import annotations

import struct

import pytest

from chimera.patching.assembler import (
    AssembleError,
    SUPPORTED_ARCHES,
    assemble,
    keystone_available,
)
from chimera.patching.binary_patcher import BinaryPatcher

ks = pytest.mark.skipif(not keystone_available(), reason="keystone not installed")


# ---------------------------- assemble() ----------------------------

@ks
def test_assemble_x86_64_known_encoding():
    assert assemble("xor eax, eax; ret", "x86_64") == bytes.fromhex("31c0c3")


@ks
def test_assemble_encodes_relative_branch_against_addr():
    """A relative jmp must encode differently depending on where it lives."""
    a = assemble("jmp 0x1010", "x86_64", addr=0x1000)
    b = assemble("jmp 0x1010", "x86_64", addr=0x1008)
    assert a != b
    # From 0x1000: 2-byte short jmp, next insn at 0x1002, disp = 0x0e → eb 0e.
    assert a == bytes.fromhex("eb0e")


def test_assemble_unknown_arch_raises():
    # Arch is validated before keystone is imported, so this holds either way.
    with pytest.raises(AssembleError):
        assemble("ret", "sparc")


def test_supported_arches_cover_the_common_set():
    for a in ("x86_64", "x86", "arm64", "arm", "thumb"):
        assert a in SUPPORTED_ARCHES


# ---------------------------- machine_arch() ----------------------------

def _min_elf(machine: int, ei_data: int = 1) -> bytes:
    endian = "<" if ei_data == 1 else ">"
    b = bytearray(64)
    b[0:4] = b"\x7fELF"
    b[4], b[5], b[6] = 2, ei_data, 1        # ELF64, endianness, version
    struct.pack_into(endian + "H", b, 0x12, machine)   # e_machine
    return bytes(b)


def _min_pe(machine: int) -> bytes:
    b = bytearray(0x100)
    b[0:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", b, 0x3C, e_lfanew)
    b[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", b, e_lfanew + 4, machine)   # COFF Machine
    return bytes(b)


@pytest.mark.parametrize("machine,expect", [
    (0x3E, "x86_64"), (0x03, "x86"), (0xB7, "arm64"), (0x28, "arm"),
    (0x1234, None),   # unknown machine → None, caller must pass arch=
])
def test_machine_arch_elf(tmp_path, machine, expect):
    f = tmp_path / "e"
    f.write_bytes(_min_elf(machine))
    assert BinaryPatcher.open(f).machine_arch() == expect


@pytest.mark.parametrize("machine,expect", [
    (0x8664, "x86_64"), (0x14C, "x86"), (0xAA64, "arm64"),
])
def test_machine_arch_pe(tmp_path, machine, expect):
    f = tmp_path / "p.exe"
    f.write_bytes(_min_pe(machine))
    assert BinaryPatcher.open(f).machine_arch() == expect


# ---------------------------- patch_asm() end-to-end ----------------------------

def _elf64_one_load(load_vaddr: int, load_size: int) -> bytes:
    """Sparse valid ELF64, one PT_LOAD mapping file offset 0 → load_vaddr."""
    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr += struct.pack("<HH", 2, 0x3E)                    # ET_EXEC, EM_X86_64
    ehdr += struct.pack("<I", 1)
    ehdr += struct.pack("<QQQ", load_vaddr, 64, 0)         # entry, phoff, shoff
    ehdr += struct.pack("<I", 0) + struct.pack("<H", 64)
    ehdr += struct.pack("<HH", 56, 1) + struct.pack("<HHH", 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, load_vaddr, load_vaddr,
                       load_size, load_size, 0x1000)
    pad = b"\x00" * (0x200 - (64 + 56))
    return ehdr + phdr + pad + b"\x00" * load_size


@ks
def test_patch_asm_assembles_at_va_and_writes(tmp_path):
    src = tmp_path / "x.elf"
    src.write_bytes(_elf64_one_load(0x400000, 0x1000))
    p = BinaryPatcher.open(src)
    # No arch passed → defaults to machine_arch() == x86_64.
    res = p.patch_asm(0x400500, "xor eax, eax; ret")
    assert res.after == bytes.fromhex("31c0c3")
    assert p.read(0x400500, 3) == bytes.fromhex("31c0c3")
