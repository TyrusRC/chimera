"""Capstone x64 disassembly fallback for PEs a disassembler's call-graph walk
can't handle (an ILT-heavy /INCREMENTAL PE64, where r2 returns nothing).

Disassembles raw bytes and, for a `call`/`jmp` that targets an Incremental
Link Table thunk, attaches the resolved real callee so an analyst reading the
listing isn't stranded on a wall of thunk stubs. Capstone is the optional
``[disasm]`` extra; without it the caller degrades to its prior behaviour.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _cs():
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: PLC0415
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    return md


def disasm_bytes(code: bytes, va: int, count: int = 64) -> list[dict]:
    """Disassemble up to `count` x64 instructions from `code` starting at `va`."""
    md = _cs()
    out: list[dict] = []
    for insn in md.disasm(code, va):
        out.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
        })
        if len(out) >= count:
            break
    return out


def annotate_ilt(insn: dict, resolver) -> None:
    """If `insn` is a call/jmp to an immediate that is an ILT thunk, record the
    real target in-place as `resolved_target`. `resolver(va)->int|None`."""
    if insn.get("mnemonic") not in ("call", "jmp"):
        return
    op = (insn.get("op_str") or "").strip()
    if not op.startswith("0x"):
        return
    try:
        target = int(op, 16)
    except ValueError:
        return
    real = resolver(target)
    if real is not None:
        insn["resolved_target"] = real


def disassemble_at(path, va: int, count: int = 64) -> list[dict] | None:
    """Disassemble `count` instructions at VA `va` in a PE, with ILT resolution.

    Returns None when capstone is absent, the file is not a parseable PE, or the
    address is not mapped — so callers can fall through to their prior path.
    """
    try:
        import pefile  # noqa: PLC0415
        from chimera.parsers.pe_pdata import resolve_thunk  # noqa: PLC0415
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        code = pe.get_memory_mapped_image()[rva:rva + count * 16]
        if not code:
            return None
        insns = disasm_bytes(code, va, count)

        def resolver(t: int):
            trva = t - image_base
            thunk = pe.get_memory_mapped_image()[trva:trva + 5]
            return resolve_thunk(thunk, t) if len(thunk) == 5 else None

        for insn in insns:
            annotate_ilt(insn, resolver)
        return insns
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("disassemble_at(%s, %#x) failed: %s", path, va, exc)
        return None
    finally:
        pe.close()
