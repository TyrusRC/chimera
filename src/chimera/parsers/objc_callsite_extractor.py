"""ObjC callsite extractor - converts r2 disassembly into ObjCCallSite records.

Walks each function's instruction stream maintaining ARM64 register state.
At each `bl objc_msgSend*` callsite, resolves the selector (from x1) and the
receiver class (from x0). Emits records compatible with link_callsites.

The extractor invokes `upgrade_to_class_symbol` BEFORE applying each
instruction so that any pending ConstantPool address landed by an earlier
adrp+add chain is promoted to a ClassSymbol in time for the call site that
follows. After emitting (or dropping) a callsite the extractor explicitly
calls `state.clobber_caller_saved()` because it `continue`s past the normal
`apply_instruction` path that would otherwise clobber for us.

Selector resolution is permissive about cstring_pool key types: int keys
(common in unit tests), `hex(addr)` strings, and `f"0x{addr:x}"` formats are
all accepted (r2 emits hex string keys, while seed/test data may use ints).
"""
from __future__ import annotations

import logging

from chimera.parsers.arm64_register_track import (
    AllocResult,
    ClassSymbol,
    ConstantPool,
    EntryX0,
    RegisterState,
    Super,
    apply_instruction,
    upgrade_to_class_symbol,
)

logger = logging.getLogger(__name__)


_MSG_SEND_TARGETS = frozenset({
    "sym.imp.objc_msgSend",
    "sym.imp.objc_msgSend_stret",
    "objc_msgSend",
    "objc_msgSend_stret",
    "_objc_msgSend",
    "_objc_msgSend_stret",
})

_MSG_SEND_SUPER_TARGETS = frozenset({
    "sym.imp.objc_msgSendSuper2",
    "sym.imp.objc_msgSendSuper2_stret",
    "objc_msgSendSuper2",
    "objc_msgSendSuper2_stret",
    "_objc_msgSendSuper2",
    "_objc_msgSendSuper2_stret",
})


def _resolve_receiver(state: RegisterState, *, is_super: bool) -> str | None:
    """Return receiver_class string from current register state, or None for dynamic."""
    if is_super:
        return "super"
    val = state.get("x0")
    if val is EntryX0:
        return "self"
    if val is Super:
        return "super"
    if isinstance(val, ClassSymbol):
        return val.name
    if isinstance(val, AllocResult):
        return val.class_name
    return None


def _resolve_selector(state: RegisterState, cstring_pool: dict) -> str | None:
    """Return selector name from current register state, or None if unresolvable."""
    val = state.get("x1")
    if isinstance(val, ConstantPool):
        # cstring_pool keys may be int OR hex string; accept both.
        sel = cstring_pool.get(val.address)
        if sel is None:
            sel = cstring_pool.get(hex(val.address))
        if sel is None:
            sel = cstring_pool.get(f"0x{val.address:x}")
        return sel
    return None


def extract_callsites(
    *,
    per_function_disasm: dict,
    class_symbols: set,
    cstring_pool: dict,
    class_address_to_name: dict[int, str] | None = None,
) -> list[dict]:
    """Extract objc_msgSend callsites from per-function disassembly.

    Args:
        per_function_disasm: {function_offset_hex: {"name": str, "ops": [...]}}.
        class_symbols: set of class names known from _OBJC_CLASS_$_ symbols.
        cstring_pool: vmaddr -> string mapping for selectors and class names.
        class_address_to_name: vmaddr -> class_name mapping for upgrading
            ConstantPool values to ClassSymbol when a register holds a class
            symbol's address.

    Returns:
        List of {caller, addr, selector, receiver_class} dicts. Callsites
        without a resolvable selector are dropped. Callsites with an
        unresolvable receiver get receiver_class=None (dynamic).
    """
    if class_address_to_name is None:
        class_address_to_name = {}
    out: list[dict] = []
    for fn_offset_str, fn_data in per_function_disasm.items():
        try:
            fn_offset = int(fn_offset_str, 16)
        except ValueError:
            continue
        ops = fn_data.get("ops", [])
        state = RegisterState()
        for insn in ops:
            insn_offset = insn.get("offset", 0)
            opcode = insn.get("opcode", "")
            target = insn.get("target_sym", "") or ""

            # Before applying, upgrade any pending class-symbol address.
            for reg in ("x0", "x1"):
                upgrade_to_class_symbol(
                    state, reg, class_address_to_name=class_address_to_name,
                )

            if opcode == "bl" and (target in _MSG_SEND_TARGETS or target in _MSG_SEND_SUPER_TARGETS):
                is_super = target in _MSG_SEND_SUPER_TARGETS
                selector = _resolve_selector(state, cstring_pool)
                if selector is None:
                    # Drop callsites with no readable selector.
                    state.clobber_caller_saved()
                    continue
                receiver = _resolve_receiver(state, is_super=is_super)
                out.append({
                    "caller": fn_offset_str,
                    "addr": hex(insn_offset) if isinstance(insn_offset, int) else str(insn_offset),
                    "selector": selector,
                    "receiver_class": receiver,
                })
                state.clobber_caller_saved()
                continue

            terminate = apply_instruction(
                state, insn, fn_offset=fn_offset, insn_offset=insn_offset,
            )
            if terminate == "ret":
                break
    return out
