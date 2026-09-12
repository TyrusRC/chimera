"""Disassemble bytes → instruction lengths (capstone) — the sizing side of the patcher.

`BinaryPatcher.nop()` must know how many bytes an instruction occupies before it
can overwrite it: is this jump the 2-byte short form or the 6-byte near form?
Hand-counting that is the exact manual step that makes "just NOP the check"
tedious (and error-prone — NOP one byte too few and you leave a live branch, one
too many and you smash the next instruction). This wraps capstone to sum the
lengths of N instructions at a VA and returns the arch-appropriate NOP fill.
capstone is an optional extra (`chimera[disasm]`); without it these raise
DisasmError with an install hint rather than ImportError.
"""
from __future__ import annotations


class DisasmError(Exception):
    """capstone missing, an unknown arch, or bytes that won't disassemble."""


# name → (CS_ARCH attr, CS_MODE attr). Mirrors assembler._ARCH_SPECS so the two
# sides of the patcher name arches identically.
_ARCH_SPECS: dict[str, tuple[str, str]] = {
    "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_32": ("CS_ARCH_X86", "CS_MODE_32"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "aarch64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "thumb": ("CS_ARCH_ARM", "CS_MODE_THUMB"),
}

# arch → single NOP encoding (little-endian bytes). x86 has a 1-byte NOP; the
# fixed-width arches repeat their whole-instruction NOP.
_NOP_FILL: dict[str, bytes] = {
    "x86_64": b"\x90",
    "x86": b"\x90",
    "x86_32": b"\x90",
    "arm64": b"\x1f\x20\x03\xd5",   # d503201f  NOP
    "aarch64": b"\x1f\x20\x03\xd5",
    "arm": b"\x00\xf0\x20\xe3",      # e320f000  NOP (A32)
    "thumb": b"\x00\xbf",            # bf00      NOP (T16)
}


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except Exception:
        return False


def _md(arch: str):
    spec = _ARCH_SPECS.get(arch.lower())
    if spec is None:
        raise DisasmError(f"unknown arch {arch!r}; supported: {', '.join(_ARCH_SPECS)}")
    try:
        import capstone
    except Exception as exc:  # pragma: no cover - only exercised without the extra
        raise DisasmError('capstone not installed — pip install "chimera[disasm]"') from exc
    return capstone.Cs(getattr(capstone, spec[0]), getattr(capstone, spec[1]))


def make_cs(arch: str, *, detail: bool = False):
    """A capstone `Cs` disassembler for `arch` (raises DisasmError if unavailable).

    Shared by the patcher's sizing and by static readers (e.g. compare-string
    recovery) that need arch-aware disassembly beyond hardcoded x64.
    """
    md = _md(arch)
    md.detail = detail
    return md


def instruction_span(code: bytes, arch: str, addr: int, count: int) -> tuple[int, list[str]]:
    """Total byte length of the first `count` instructions in `code`, plus their text.

    Raises DisasmError if fewer than `count` instructions decode (the bytes ran
    out mid-instruction) — refusing beats NOPing a partial instruction.
    """
    if count < 1:
        raise DisasmError("count must be >= 1")
    md = _md(arch)
    total = 0
    texts: list[str] = []
    for insn in md.disasm(bytes(code), addr):
        total += insn.size
        texts.append(f"{insn.mnemonic} {insn.op_str}".strip())
        if len(texts) >= count:
            return total, texts
    raise DisasmError(
        f"only {len(texts)} instruction(s) decoded at {addr:#x}, needed {count}")


def nop_fill(arch: str, length: int) -> bytes:
    """`length` bytes of the arch's NOP. Length must be a multiple of the NOP width."""
    unit = _NOP_FILL.get(arch.lower())
    if unit is None:
        raise DisasmError(f"no NOP encoding for arch {arch!r}")
    if length % len(unit) != 0:
        raise DisasmError(
            f"cannot fill {length} bytes with a {len(unit)}-byte {arch} NOP "
            f"(not a multiple) — the span does not align to whole instructions")
    return unit * (length // len(unit))
