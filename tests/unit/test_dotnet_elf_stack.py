"""Neutralize an ELF's exec-stack requirement so it loads on hardened kernels.

MonoMod (under Harmony) ships a tiny native helper with no PT_GNU_STACK
header, which makes the loader assume an executable stack is needed — and a
hardened WSL2 / grsec kernel then refuses `dlopen` with "cannot enable
executable stack as shared object requires". Converting the helper's
PT_GNU_EH_FRAME header into a non-executable PT_GNU_STACK marker tells the
loader the stack is safe.
"""
from __future__ import annotations

import struct

import pytest

from chimera.dotnet.elf_stack import (
    clear_exec_stack_requirement,
    _iter_program_headers,
)

PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551


def _minimal_elf64(program_headers):
    """Build a 64-bit ELF with the given (p_type, p_flags) program headers."""
    phnum = len(program_headers)
    ehsize = 64
    phentsize = 56
    phoff = ehsize
    buf = bytearray(ehsize + phnum * phentsize)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2      # ELFCLASS64
    buf[5] = 1      # little-endian
    struct.pack_into("<Q", buf, 0x20, phoff)
    struct.pack_into("<H", buf, 0x36, phentsize)
    struct.pack_into("<H", buf, 0x38, phnum)
    for i, (ptype, pflags) in enumerate(program_headers):
        ph = phoff + i * phentsize
        struct.pack_into("<I", buf, ph, ptype)
        struct.pack_into("<I", buf, ph + 4, pflags)
    return bytes(buf)


def test_converts_eh_frame_into_nonexec_gnu_stack():
    elf = _minimal_elf64([(0x1, 0x5), (PT_GNU_EH_FRAME, 0x4)])
    patched, n = clear_exec_stack_requirement(elf)
    assert n == 1
    types = [t for t, _ in _iter_program_headers(patched)]
    assert PT_GNU_STACK in types
    assert PT_GNU_EH_FRAME not in types
    # The new marker must be non-executable.
    flags = dict(_iter_program_headers(patched))[PT_GNU_STACK]
    assert flags & 0x1 == 0  # PF_X cleared


def test_clears_exec_bit_on_existing_gnu_stack():
    elf = _minimal_elf64([(0x1, 0x6), (PT_GNU_STACK, 0x7)])  # RWX stack
    patched, n = clear_exec_stack_requirement(elf)
    assert n == 1
    flags = dict(_iter_program_headers(patched))[PT_GNU_STACK]
    assert flags & 0x1 == 0


def test_no_change_when_already_safe():
    elf = _minimal_elf64([(0x1, 0x5), (PT_GNU_STACK, 0x6)])  # RW stack, fine
    patched, n = clear_exec_stack_requirement(elf)
    assert n == 0
    assert patched == elf


def test_patch_embedded_elf_inside_a_larger_blob():
    """MonoMod embeds the helper inside a managed DLL — patch it in place."""
    elf = _minimal_elf64([(0x1, 0x5), (PT_GNU_EH_FRAME, 0x4)])
    blob = b"MZ\x00\x00padding..." + elf + b"trailing resource bytes"
    patched, n = clear_exec_stack_requirement(blob)
    assert n == 1
    assert patched[:len(b"MZ\x00\x00padding...")] == b"MZ\x00\x00padding..."
    assert patched.endswith(b"trailing resource bytes")


def test_rejects_non_elf_input():
    with pytest.raises(ValueError):
        clear_exec_stack_requirement(b"not an elf at all")


def test_ignores_32bit_elf():
    # We only ship 64-bit helpers; a 32-bit one is left untouched, not crashed.
    elf = bytearray(_minimal_elf64([(PT_GNU_EH_FRAME, 0x4)]))
    elf[4] = 1  # ELFCLASS32
    with pytest.raises(ValueError):
        clear_exec_stack_requirement(bytes(elf))
