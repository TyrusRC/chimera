"""Unit tests for the ELF header parser.

Synthesized minimal ELFs are tedious to build by hand; we use Python's
own `_winreg`-free pure-bytes approach. For broader coverage, Task 22's
fixture-based integration tests will hit a real `/usr/bin/ls` style binary.
"""
import struct
from pathlib import Path

import pytest

elftools = pytest.importorskip("elftools")

from chimera.parsers.elf_header import parse_elf, ELFHeaderInfo


def _build_minimal_elf64_exe(path: Path) -> Path:
    """Build a minimal valid ELF64 EXEC with no dynamic section.

    pyelftools is forgiving about missing sections; just need ehdr + phdr.
    """
    # ELF64 header layout
    # e_ident: 16 bytes (magic + class + data + version + osabi + ...)
    # e_type, e_machine: uint16
    # e_version: uint32
    # e_entry, e_phoff, e_shoff: uint64
    # e_flags: uint32
    # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx: uint16
    EHSIZE = 64
    PHENTSIZE = 56  # ELF64
    ehdr = bytearray(EHSIZE)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2     # ELFCLASS64
    ehdr[5] = 1     # ELFDATA2LSB
    ehdr[6] = 1     # EV_CURRENT
    ehdr[7] = 0     # ELFOSABI_NONE
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     2,       # e_type = ET_EXEC
                     0x3e,    # e_machine = EM_X86_64
                     1,       # e_version
                     0x401000,  # e_entry
                     EHSIZE,  # e_phoff (right after ehdr)
                     0,       # e_shoff
                     0,       # e_flags
                     EHSIZE,  # e_ehsize
                     PHENTSIZE,  # e_phentsize
                     0,       # e_phnum (no segments — pyelftools tolerates)
                     0,       # e_shentsize
                     0,       # e_shnum
                     0)       # e_shstrndx
    path.write_bytes(bytes(ehdr))
    return path


def test_parse_elf_minimal_exec(tmp_path):
    p = _build_minimal_elf64_exe(tmp_path / "hello")
    info = parse_elf(p)
    assert info.file_class == "ELF64"
    assert info.machine == "x86_64"
    assert info.e_type == "ET_EXEC"
    assert info.entry_point == 0x401000
    assert info.dynamic_linker is None
    assert info.needed == []
    assert info.relro == "none"
    assert info.pie is False
    # No sections written — synthesized ELF has e_shnum=0
    assert info.has_symbols is False
    assert info.is_stripped is True


def test_parse_elf_on_real_system_binary():
    """Test parser on a real ELF if the system has one. Best-effort."""
    candidates = [Path("/bin/ls"), Path("/usr/bin/ls"), Path("/bin/cat")]
    binary = next((c for c in candidates if c.exists() and c.is_file()), None)
    if binary is None:
        pytest.skip("no system ELF available")
    info = parse_elf(binary)
    # /bin/ls is dynamically linked: should have a dynamic linker and NEEDED libs
    assert info.machine in ("x86_64", "arm64", "arm")
    assert info.dynamic_linker is not None
    assert len(info.needed) > 0
    # /bin/ls is typically PIE on modern distros
    # but accept either since CI might differ. Assert sane ELF-ness:
    assert info.e_type in ("ET_DYN", "ET_EXEC")
