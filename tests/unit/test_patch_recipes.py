"""Recipe loader + applier — verifies each `kind` ends up writing the right bytes."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera.patching.binary_patcher import (
    BinaryFormat,
    BinaryPatcher,
    PatchError,
)
from chimera.patching.recipes import (
    Recipe,
    apply_recipe,
    load_bundled_recipes,
)


FIXTURES = Path(__file__).resolve().parents[2] / "e2e" / "material" / "desktop"


def test_load_bundled_recipes_includes_pe_isdbg():
    recipes = load_bundled_recipes()
    assert "pe-isdebuggerpresent-nop" in recipes
    r = recipes["pe-isdebuggerpresent-nop"]
    assert "pe" in r.applies_to
    assert len(r.patches) >= 1


def test_apply_recipe_rejects_wrong_format(tmp_path):
    src = tmp_path / "x.elf"
    src.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256)
    p = BinaryPatcher.open(src)
    pe_only = Recipe(name="pe-only", description="", applies_to=["pe"], patches=[])
    with pytest.raises(PatchError):
        apply_recipe(p, pe_only)


def test_write_bytes_step_applies_at_va(tmp_path):
    """Synthesise a one-LOAD-segment ELF so write-bytes has a real VA to hit."""
    src = tmp_path / "x.elf"
    src.write_bytes(_minimal_elf64_with_one_load(load_vaddr=0x400000, load_size=0x1000))
    p = BinaryPatcher.open(src)
    r = Recipe(
        name="t", description="", applies_to=["elf"],
        patches=[{"kind": "write-bytes", "address": "0x400100", "bytes_hex": "deadbeef"}],
    )
    results = apply_recipe(p, r)
    assert len(results) == 1
    assert results[0].after == bytes.fromhex("deadbeef")
    # Read-back through the patcher confirms the on-disk image was mutated.
    assert p.read(0x400100, 4) == bytes.fromhex("deadbeef")


def test_nop_range_fills_with_x86_nop(tmp_path):
    src = tmp_path / "x.elf"
    src.write_bytes(_minimal_elf64_with_one_load(load_vaddr=0x400000, load_size=0x1000))
    p = BinaryPatcher.open(src)
    r = Recipe(
        name="nop", description="", applies_to=["elf"],
        patches=[{"kind": "nop-range", "start": "0x400200", "end": "0x400208"}],
    )
    results = apply_recipe(p, r)
    assert results[0].after == b"\x90" * 8


def test_force_jump_taken_flips_jz(tmp_path):
    src = tmp_path / "x.elf"
    raw = bytearray(_minimal_elf64_with_one_load(load_vaddr=0x400000, load_size=0x1000))
    # Plant a 0x74 (jz) at file offset matching VA 0x400500.
    file_off = 0x500   # because we placed our single LOAD seg with p_offset==p_vaddr offset 0
    raw[file_off] = 0x74
    src.write_bytes(bytes(raw))

    p = BinaryPatcher.open(src)
    r = Recipe(
        name="flip", description="", applies_to=["elf"],
        patches=[{"kind": "force-jump-taken", "address": "0x400500"}],
    )
    apply_recipe(p, r)
    assert p.read(0x400500, 1) == b"\xEB"


def test_force_jump_taken_rejects_non_conditional(tmp_path):
    src = tmp_path / "x.elf"
    src.write_bytes(_minimal_elf64_with_one_load(load_vaddr=0x400000, load_size=0x1000))
    p = BinaryPatcher.open(src)
    r = Recipe(
        name="flip", description="", applies_to=["elf"],
        patches=[{"kind": "force-jump-taken", "address": "0x400500"}],
    )
    with pytest.raises(PatchError):
        apply_recipe(p, r)


def test_unknown_kind_raises(tmp_path):
    src = tmp_path / "x.elf"
    src.write_bytes(_minimal_elf64_with_one_load(load_vaddr=0x400000, load_size=0x1000))
    p = BinaryPatcher.open(src)
    r = Recipe(
        name="bad", description="", applies_to=["elf"],
        patches=[{"kind": "no-such-kind", "address": "0x400000"}],
    )
    with pytest.raises(PatchError):
        apply_recipe(p, r)


def test_load_recipe_from_file(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({
        "name": "demo",
        "description": "d",
        "applies_to": ["elf"],
        "patches": [{"kind": "write-bytes", "address": "0x400100", "bytes_hex": "00"}],
    }))
    r = Recipe.from_file(p)
    assert r.name == "demo"
    assert r.patches[0]["bytes_hex"] == "00"


@pytest.mark.skipif(not (FIXTURES / "hello").exists(), reason="hello ELF missing")
def test_elf_plt_stub_recipe_on_fixture(tmp_path):
    """The fixture is built without ptrace, so the recipe should report 'not found' — that's the correct, conservative behaviour. We just verify the resolver raises a clean PatchError."""
    p = BinaryPatcher.open(FIXTURES / "hello")
    recipe = Recipe(
        name="ptrace-zero", description="", applies_to=["elf"],
        patches=[{
            "kind": "find-elf-plt-and-stub",
            "symbol_name": "ptrace",
            "stub_bytes_hex": "31c0c3",
        }],
    )
    with pytest.raises(PatchError, match="ptrace"):
        apply_recipe(p, recipe)


# ---------- helpers ----------

def _minimal_elf64_with_one_load(*, load_vaddr: int, load_size: int) -> bytes:
    """Synth a sparse but valid ELF64 with one PT_LOAD segment.

    Layout::
        [ELF header  | 64 bytes]
        [PT_LOAD ph  | 56 bytes]
        [...padding to 0x200 ...]
        [LOAD payload @ file offset 0x200, length=load_size]

    The PT_LOAD maps file offset 0 -> vaddr `load_vaddr`, so a VA inside
    [load_vaddr, load_vaddr+load_size) resolves to (VA - load_vaddr).
    Tests use this to validate the patcher's address translation without
    needing the system toolchain to build a real ELF.
    """
    import struct
    ehsize = 64
    phentsize = 56
    phnum = 1
    ph_off = ehsize
    # Place the LOAD body at p_offset=0 so VA→offset is just (VA - vaddr).
    p_offset = 0
    p_filesz = load_size

    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8       # e_ident
    ehdr += struct.pack("<HH", 2, 0x3E)                    # e_type=ET_EXEC, e_machine=EM_X86_64
    ehdr += struct.pack("<I", 1)                            # e_version
    ehdr += struct.pack("<QQQ", load_vaddr, ph_off, 0)      # entry, phoff, shoff
    ehdr += struct.pack("<I", 0)                            # flags
    ehdr += struct.pack("<H", ehsize)                       # ehsize
    ehdr += struct.pack("<HH", phentsize, phnum)            # phentsize, phnum
    ehdr += struct.pack("<HHH", 0, 0, 0)                    # shentsize, shnum, shstrndx
    assert len(ehdr) == ehsize, len(ehdr)

    # ELF64 program header.
    p_type = 1       # PT_LOAD
    p_flags = 5      # R+X
    phdr = struct.pack("<IIQQQQQQ",
                       p_type, p_flags,
                       p_offset, load_vaddr, load_vaddr,
                       p_filesz, p_filesz, 0x1000)

    pad = b"\x00" * (0x200 - (ehsize + phentsize))
    body = b"\x00" * load_size
    return ehdr + phdr + pad + body
