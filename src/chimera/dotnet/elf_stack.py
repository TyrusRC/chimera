"""Make an ELF loadable on a kernel that refuses executable stacks.

MonoMod's runtime-detour helper (loaded by Harmony) has no PT_GNU_STACK
program header, so the dynamic loader assumes it needs an executable stack.
A hardened kernel then refuses `dlopen` with "cannot enable executable
stack as shared object requires", which breaks any Harmony-based trace on
WSL2 and similar. Marking the stack non-executable removes the demand.
"""
from __future__ import annotations

import struct
from typing import Iterator

_PT_GNU_EH_FRAME = 0x6474E550
_PT_GNU_STACK = 0x6474E551
_PF_X = 0x1


def _elf_offset(blob: bytes) -> int:
    """Byte offset of the 64-bit ELF image in `blob`, or raise ValueError."""
    off = blob.find(b"\x7fELF")
    if off == -1:
        raise ValueError("no ELF image found")
    if blob[off + 4] != 2:  # not ELFCLASS64
        raise ValueError("only 64-bit ELF is supported")
    return off


def _iter_program_headers(blob: bytes) -> Iterator[tuple[int, int]]:
    """Yield (p_type, p_flags) for each program header of the ELF in `blob`."""
    off = _elf_offset(blob)
    phoff = struct.unpack_from("<Q", blob, off + 0x20)[0]
    phentsize = struct.unpack_from("<H", blob, off + 0x36)[0]
    phnum = struct.unpack_from("<H", blob, off + 0x38)[0]
    for i in range(phnum):
        ph = off + phoff + i * phentsize
        p_type = struct.unpack_from("<I", blob, ph)[0]
        p_flags = struct.unpack_from("<I", blob, ph + 4)[0]
        yield p_type, p_flags


def clear_exec_stack_requirement(blob: bytes) -> tuple[bytes, int]:
    """Return (patched_blob, changes) with the ELF's stack marked non-exec.

    Two cases are handled:
    * an explicit PT_GNU_STACK with PF_X set — the exec bit is cleared;
    * no PT_GNU_STACK at all — the PT_GNU_EH_FRAME header is repurposed into
      a non-executable PT_GNU_STACK marker (losing unwind info for what is a
      leaf trampoline, which is harmless).

    `blob` may be the bare ELF or a larger container (e.g. a managed DLL with
    the helper embedded as a resource); the surrounding bytes are preserved.
    """
    data = bytearray(blob)
    off = _elf_offset(data)
    phoff = struct.unpack_from("<Q", data, off + 0x20)[0]
    phentsize = struct.unpack_from("<H", data, off + 0x36)[0]
    phnum = struct.unpack_from("<H", data, off + 0x38)[0]

    types = [t for t, _ in _iter_program_headers(data)]
    changes = 0

    for i in range(phnum):
        ph = off + phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, ph)[0]
        p_flags = struct.unpack_from("<I", data, ph + 4)[0]

        if p_type == _PT_GNU_STACK and (p_flags & _PF_X):
            struct.pack_into("<I", data, ph + 4, p_flags & ~_PF_X)
            changes += 1
        elif p_type == _PT_GNU_EH_FRAME and _PT_GNU_STACK not in types:
            struct.pack_into("<I", data, ph, _PT_GNU_STACK)
            struct.pack_into("<I", data, ph + 4, 0x6)  # RW, no X
            # Zero the location/size fields so it is a pure marker.
            for field_off in (8, 16, 24, 32, 40):
                struct.pack_into("<Q", data, ph + field_off, 0)
            changes += 1
            break

    return bytes(data), changes
