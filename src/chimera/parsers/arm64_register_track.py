"""ARM64 register state vocabulary for ObjC callsite extraction.

Pure-data tracker. The extractor walks instructions, calls apply_instruction
to update state, and inspects state at each `bl objc_msgSend*` callsite.

NOTE on `objc_alloc_init`: the iOS 9+ fused `objc_alloc_init` returns an
already-initialized instance — semantically `[[ClassName alloc] init]`. The
tracker records `AllocResult(class_name)` for both `objc_alloc` and
`objc_alloc_init`. Downstream callers should NOT synthesize a paired
`-init` callsite for `objc_alloc_init`; the state correctly represents the
instance reference, so any subsequent selector dispatch on x0 resolves to
the correct receiver class.

NOTE on upgrade_to_class_symbol: the extractor must invoke this helper after
each instruction that may have landed a class-symbol address in a register
(adrp+add chains, cross-register ldr). The tracker itself does not call it
automatically because the address-to-name mapping is maintained outside the
tracker module.
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


# Targets that should be treated as objc_alloc / objc_alloc_init. Covers the
# naming variants r2 may emit depending on symbol stripping/normalization.
_OBJC_ALLOC_TARGETS = frozenset({
    "sym.imp.objc_alloc",
    "sym.imp.objc_alloc_init",
    "objc_alloc",
    "objc_alloc_init",
    "_objc_alloc",
    "_objc_alloc_init",
})


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

    if opcode == "ldr" and len(ops) >= 2:
        dest = ops[0]
        src = ops[1] if len(ops) >= 2 else None
        imm = ops[2] if len(ops) >= 3 and isinstance(ops[2], int) else 0
        if isinstance(src, str) and (src.startswith("x") or src.startswith("w")):
            cur = state.get(src if src.startswith("x") else f"x{src[1:]}")
            if isinstance(cur, ConstantPool):
                # Cross-register load: dest gets the address pointed at.
                # If the deref target is a tracked class symbol, the
                # extractor's upgrade_to_class_symbol pass will refine.
                state.set(dest, ConstantPool(cur.address + imm))
                return None

    if opcode == "mov" and len(ops) >= 2 and ops[1] == "x0":
        # Function-prologue receiver save?
        if insn_offset - fn_offset <= _PROLOGUE_WINDOW_BYTES:
            state.set(ops[0], EntryX0)
            return None

    if opcode == "mov" and len(ops) >= 2 \
            and isinstance(ops[0], str) and isinstance(ops[1], str) \
            and ops[0].startswith("x") and ops[1].startswith("x"):
        # Generic register-to-register copy: propagate the source value.
        # Needed so receiver-restore patterns like `mov x0, x19` (where x19
        # was set to EntryX0 in the prologue) place EntryX0 into x0 in time
        # for a subsequent objc_msgSend dispatch.
        # Generic register-to-register mov: copy source state to dest. Source
        # may be Unknown — overwriting dest with Unknown is intentional (a real
        # mov clobbers any prior tracked value of the destination).
        state.set(ops[0], state.get(ops[1]))
        return None

    if opcode == "bl":
        target = insn.get("target_sym", "") or ""
        if target in _OBJC_ALLOC_TARGETS:
            # Read x0 BEFORE clobbering caller-saved.
            cur_x0 = state.get("x0")
            if isinstance(cur_x0, ClassSymbol):
                state.clobber_caller_saved()
                state.set("x0", AllocResult(cur_x0.name))
                return None
        # Generic call: clobber caller-saved (x0..x18) per AAPCS64.
        state.clobber_caller_saved()
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


def upgrade_to_class_symbol(
    state: RegisterState,
    reg: str,
    *,
    class_address_to_name: dict[int, str],
) -> None:
    """Upgrade `state[reg]` from ConstantPool(addr) to ClassSymbol(name) when
    `addr` matches a known _OBJC_CLASS_$_<name> symbol address.

    No-op if `state[reg]` is not a ConstantPool, or if its address isn't in
    the supplied map.
    """
    cur = state.get(reg)
    if isinstance(cur, ConstantPool):
        name = class_address_to_name.get(cur.address)
        if name is not None:
            state.set(reg, ClassSymbol(name))
