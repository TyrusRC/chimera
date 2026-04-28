"""ARM64 register state vocabulary for ObjC callsite extraction.

Pure-data tracker. The extractor walks instructions, calls apply_instruction
to update state, and inspects state at each `bl objc_msgSend*` callsite.
"""
from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Value types - what we know about a register at a given program point
# ---------------------------------------------------------------------------

class _Singleton:
    """Marker objects shared via identity comparison."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


Unknown = _Singleton("Unknown")
"""Register value not statically resolvable."""

EntryX0 = _Singleton("EntryX0")
"""Saved x0 from function entry - receiver of an instance method."""

Super = _Singleton("Super")
"""Pointer to an objc_super struct - used by [super ...] dispatch."""


@dataclass(frozen=True)
class ConstantPool:
    """Register holds an address loaded from the constant pool."""
    address: int


@dataclass(frozen=True)
class ClassSymbol:
    """Register holds the address of an _OBJC_CLASS_$_<name> symbol."""
    name: str


@dataclass(frozen=True)
class AllocResult:
    """Register holds the result of [<ClassName> alloc] / objc_alloc()."""
    class_name: str


# Union of all register-value types. Use this in callers' annotations
# instead of `object` to keep type information through extractor logic.
RegValue = ConstantPool | ClassSymbol | AllocResult | _Singleton


# ---------------------------------------------------------------------------
# State container
# ---------------------------------------------------------------------------

# AAPCS64: x0..x18 are caller-saved. x19..x28 are callee-saved.
_CALLER_SAVED = tuple(f"x{i}" for i in range(19))


class RegisterState:
    """Map register name -> value. Defaults to Unknown for unset registers."""

    __slots__ = ("_regs",)

    def __init__(self) -> None:
        self._regs: dict[str, RegValue] = {}

    def get(self, reg: str) -> RegValue:
        return self._regs.get(reg, Unknown)

    def set(self, reg: str, value: RegValue) -> None:
        self._regs[reg] = value

    def clobber_caller_saved(self) -> None:
        """Reset x0..x18 to Unknown (per AAPCS64 call clobber rules)."""
        for r in _CALLER_SAVED:
            self._regs.pop(r, None)


# ---------------------------------------------------------------------------
# Instruction application
# ---------------------------------------------------------------------------

# Prologue window: mov xN, x0 in this many bytes from function entry counts
# as "saved receiver" rather than a generic register copy.
_PROLOGUE_WINDOW_BYTES = 0x40  # 16 instructions @ 4 bytes each


def apply_instruction(
    state: RegisterState,
    insn: dict,
    *,
    fn_offset: int,
    insn_offset: int,
) -> str | None:
    """Update `state` based on `insn`. Returns 'ret' on terminator, else None.

    `insn` is the normalized op shape: {"opcode": str, "operands": [...]}.
    `fn_offset` is the function's start address; `insn_offset` is the current
    instruction's address. Both used to detect prologue context for entry-x0.
    """
    opcode = insn.get("opcode", "")
    ops = insn.get("operands", [])

    if opcode == "ret":
        return "ret"

    if opcode == "adrp" and len(ops) >= 2 and isinstance(ops[1], int):
        state.set(ops[0], ConstantPool(ops[1]))
        return None

    if opcode == "add" and len(ops) >= 3:
        # add xN, xN, imm -- refine ConstantPool anchor.
        dest, lhs = ops[0], ops[1]
        imm = ops[2] if isinstance(ops[2], int) else None
        if dest == lhs and imm is not None:
            cur = state.get(dest)
            if isinstance(cur, ConstantPool):
                state.set(dest, ConstantPool(cur.address + imm))
                return None

    if opcode == "mov" and len(ops) >= 2 and ops[1] == "x0":
        # Function-prologue receiver save?
        if insn_offset - fn_offset <= _PROLOGUE_WINDOW_BYTES:
            state.set(ops[0], EntryX0)
            return None

    # Default rule: opcode with a register destination clobbers it.
    # ARM64 'w' registers alias the lower 32 bits of 'x' — clobber the x-view too.
    if ops and isinstance(ops[0], str):
        dest = ops[0]
        if dest.startswith("x"):
            state.set(dest, Unknown)
        elif dest.startswith("w") and dest[1:].isdigit():
            state.set(f"x{dest[1:]}", Unknown)
    return None
