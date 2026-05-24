"""Bundled patch recipes — pattern-match + apply.

A recipe is a JSON spec that names a class of patch ("nop the
IsDebuggerPresent caller", "force a conditional jump taken") and ships
the byte-level rewriting logic to apply it against a binary.

Recipes are intentionally narrow: each one targets *one* anti-RE
control. Stacking them is the analyst's call — `chimera patch <bin>
--recipe a --recipe b` applies them in order.

JSON shape::

    {
      "name": "pe-isdebuggerpresent-nop",
      "description": "...",
      "applies_to": ["pe"],                # one of pe/elf/macho
      "patches": [
        {"kind": "find-import-and-stub",
         "import_name": "IsDebuggerPresent",
         "stub_bytes_hex": "31c0c3"}       # xor eax,eax; ret
      ]
    }

Available patch kinds (`kind`):
  * ``find-import-and-stub``  — locate an imported function in the PE
    import directory; rewrite its IAT-pointed thunk to a short stub.
    Only the *thunk* changes; callers are not touched, so any
    cross-reference still resolves to the patched implementation.
  * ``find-elf-plt-and-stub`` — analogous for ELF: rewrite the PLT stub
    for a chosen dynamic symbol to a constant-return shim.
  * ``nop-range``             — analyst-supplied [start, end) VA range
    filled with 0x90 / 0x00 / no-op equivalent for the binary's arch.
  * ``force-jump-taken``      — flip a single short conditional jump
    (0x74 jz / 0x75 jnz / etc.) at the supplied VA to an
    unconditional ``jmp`` (0xEB).
  * ``write-bytes``           — last-resort: write raw bytes at VA.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chimera.patching.binary_patcher import (
    BinaryFormat,
    BinaryPatcher,
    PatchError,
    PatchPlan,
    PatchResult,
)

logger = logging.getLogger(__name__)

BUNDLED_RECIPES_DIR = Path(__file__).resolve().parent / "recipe_packs"


@dataclass
class Recipe:
    name: str
    description: str
    applies_to: list[str]
    patches: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Recipe":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            applies_to=list(d.get("applies_to") or []),
            patches=list(d.get("patches") or []),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Recipe":
        return cls.from_dict(json.loads(path.read_text()))


def load_bundled_recipes(directory: Path | None = None) -> dict[str, Recipe]:
    """Read every `*.json` in the recipes directory; key by recipe name."""
    out: dict[str, Recipe] = {}
    base = Path(directory) if directory else BUNDLED_RECIPES_DIR
    if not base.exists():
        return out
    for fp in sorted(base.glob("*.json")):
        try:
            r = Recipe.from_file(fp)
            out[r.name] = r
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            logger.warning("recipe %s unreadable: %s", fp, exc)
    return out


def apply_recipe(patcher: BinaryPatcher, recipe: Recipe) -> list[PatchResult]:
    """Apply every patch step in the recipe; return the results.

    Steps run in order. A failing step raises and the caller decides
    whether to save the partial state or discard it — recipes are
    expected to be small and atomic in practice.
    """
    fmt_str = patcher.fmt.value
    if recipe.applies_to and fmt_str not in recipe.applies_to:
        raise PatchError(
            f"Recipe {recipe.name!r} does not apply to {fmt_str.upper()} "
            f"(supports: {', '.join(recipe.applies_to)})"
        )

    results: list[PatchResult] = []
    for i, step in enumerate(recipe.patches):
        kind = step.get("kind")
        try:
            plans = _expand_step(patcher, recipe, step)
        except PatchError:
            raise
        except Exception as exc:
            raise PatchError(f"recipe {recipe.name!r} step {i} ({kind}): {exc}") from exc
        for plan in plans:
            results.append(patcher.apply(plan))
    return results


def _expand_step(patcher: BinaryPatcher, recipe: Recipe, step: dict[str, Any]) -> list[PatchPlan]:
    kind = step.get("kind", "")
    if kind == "write-bytes":
        vaddr = _hex_int(step["address"])
        data = bytes.fromhex(step["bytes_hex"])
        return [PatchPlan(bytes_=data, virtual_address=vaddr, description=f"{recipe.name}: write")]
    if kind == "nop-range":
        start = _hex_int(step["start"])
        end = _hex_int(step["end"])
        if end <= start:
            raise ValueError(f"nop-range end {end:#x} <= start {start:#x}")
        nop = bytes([_nop_for_format(patcher.fmt)] * (end - start))
        return [PatchPlan(bytes_=nop, virtual_address=start, description=f"{recipe.name}: nop {end-start} bytes")]
    if kind == "force-jump-taken":
        vaddr = _hex_int(step["address"])
        existing = patcher.read(vaddr, 1)
        if existing[0] not in _SHORT_COND_JUMPS:
            raise PatchError(
                f"address {vaddr:#x} is not a short conditional jump "
                f"(found {existing[0]:#x})"
            )
        return [PatchPlan(bytes_=b"\xEB", virtual_address=vaddr,
                          description=f"{recipe.name}: jmp short forced")]
    if kind == "find-import-and-stub":
        import_name = step["import_name"]
        stub = bytes.fromhex(step["stub_bytes_hex"])
        target_va = _resolve_pe_import(patcher, import_name)
        return [PatchPlan(bytes_=stub, virtual_address=target_va,
                          description=f"{recipe.name}: stub {import_name}")]
    if kind == "find-elf-plt-and-stub":
        symbol_name = step["symbol_name"]
        stub = bytes.fromhex(step["stub_bytes_hex"])
        target_va = _resolve_elf_plt(patcher, symbol_name)
        return [PatchPlan(bytes_=stub, virtual_address=target_va,
                          description=f"{recipe.name}: stub PLT@{symbol_name}")]
    raise PatchError(f"unknown patch kind {kind!r}")


def _hex_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 16)


def _nop_for_format(fmt: BinaryFormat) -> int:
    """Return the 1-byte NOP opcode appropriate for the format/arch.

    x86 / x86_64 → 0x90. ARM has no 1-byte NOP — recipes targeting ARM
    must supply an explicit `bytes_hex` step.
    """
    if fmt in (BinaryFormat.PE, BinaryFormat.ELF, BinaryFormat.MACHO):
        return 0x90
    return 0x00


# Opcodes for the short (1-byte) conditional jumps in x86 / x86_64.
# Long (0F 8x) forms aren't handled here — recipes that need them should
# use ``write-bytes`` with the 6-byte form.
_SHORT_COND_JUMPS = {
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
}


# ---------- PE import resolver ----------------------------------------------

def _resolve_pe_import(patcher: BinaryPatcher, symbol_name: str) -> int:
    """Return the VA of the IAT slot for `symbol_name`.

    Uses pefile because manually walking the import descriptor + ILT is
    a lot of code for one helper. If pefile isn't installed (highly
    unlikely; chimera depends on it), the caller gets a clear error.
    """
    try:
        import pefile
    except ImportError as exc:
        raise PatchError(f"pefile not available: {exc}") from exc
    pe = pefile.PE(data=bytes(patcher.buffer), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name and imp.name.decode(errors="replace") == symbol_name:
                    return imp.address
    finally:
        pe.close()
    raise PatchError(f"PE import {symbol_name!r} not found in any descriptor")


# ---------- ELF PLT resolver ------------------------------------------------

def _resolve_elf_plt(patcher: BinaryPatcher, symbol_name: str) -> int:
    """Return the VA of the PLT stub bound to `symbol_name`.

    We walk the .plt section header and pair it with .rela.plt entries to
    find the slot index for the symbol — this avoids the heavyweight
    PT_DYNAMIC walker pyelftools exposes.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise PatchError(f"pyelftools not available: {exc}") from exc

    bio = _ByteIO(bytes(patcher.buffer))
    elf = ELFFile(bio)

    plt_sec = elf.get_section_by_name(".plt") or elf.get_section_by_name(".plt.sec")
    if plt_sec is None:
        raise PatchError("ELF has no .plt section")

    rela = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    if rela is None:
        raise PatchError("ELF has no .rela.plt section")

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        raise PatchError("ELF has no .dynsym section")

    # Each PLT entry is 16 bytes on x86_64. The first entry is the
    # resolver thunk, so symbol-bound stubs start at index 1.
    entry_size = 16
    for i, reloc in enumerate(rela.iter_relocations()):
        sym = dynsym.get_symbol(reloc["r_info_sym"])
        if sym.name == symbol_name:
            return plt_sec["sh_addr"] + (i + 1) * entry_size
    raise PatchError(f"ELF PLT entry for {symbol_name!r} not found")


class _ByteIO:
    """Minimal file-like wrapper around a bytes buffer for ELFFile."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        end = len(self._data) if n < 0 else self._pos + n
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = off
        elif whence == 1:
            self._pos += off
        elif whence == 2:
            self._pos = len(self._data) + off
        return self._pos

    def tell(self) -> int:
        return self._pos
