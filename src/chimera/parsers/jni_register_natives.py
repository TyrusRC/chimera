"""Recover `RegisterNatives` dynamic JNI bindings from native disasm.

`JNIEnv` is a pointer to a function table; `RegisterNatives` lives at
offset 0xd0 on AArch64 (slot 215). r2 annotates indirect calls through
known offsets with `*RegisterNatives` in the disasm comment field —
this is what we grep for. Misses: heavily obfuscated bindings (slot
indirection through helper, encrypted vtables) — caller increments
`unresolved` accordingly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_RN_HINT_RX = re.compile(r"\*RegisterNatives|RegisterNatives\b")


@dataclass
class RegisterNativesCall:
    caller_addr: str
    call_addr: str


def find_register_natives_calls(
    per_function_disasm: dict[str, dict],
) -> list[RegisterNativesCall]:
    out: list[RegisterNativesCall] = []
    for caller_addr, fn in per_function_disasm.items():
        for op in fn.get("ops") or []:
            if op.get("type") not in ("ucall", "ccall", "call"):
                continue
            disasm = op.get("disasm") or op.get("opcode") or ""
            if _RN_HINT_RX.search(disasm):
                out.append(RegisterNativesCall(
                    caller_addr=caller_addr,
                    call_addr=op.get("offset", caller_addr),
                ))
    return out


@dataclass
class RegisterNativesEntry:
    method_name: str
    signature: str
    fn_addr: str


_ADRP_RX = re.compile(r"adrp\s+(?P<reg>[xw]\d+)\s*,\s*(?P<imm>0x[0-9a-fA-F]+)")
_ADD_RX = re.compile(r"add\s+(?P<dst>[xw]\d+)\s*,\s*(?P<src>[xw]\d+)\s*,\s*(?P<imm>(?:0x)?[0-9a-fA-F]+)")
_MOV_IMM_RX = re.compile(r"mov\s+(?P<reg>[xw]\d+)\s*,\s*#?(?P<imm>(?:0x)?[0-9a-fA-F]+)")


def _parse_imm(s: str) -> int:
    return int(s, 16) if s.startswith("0x") else int(s)


def _track_register_value(ops: list[dict], reg: str, until_idx: int) -> int | None:
    """Walk ops[:until_idx] backwards; return the resolved literal value
    of `reg` if reachable through `adrp+add` or `mov #imm`. None on
    failure.
    """
    val: int | None = None
    base: int | None = None
    for op in reversed(ops[:until_idx]):
        d = op.get("disasm", "")
        m = _MOV_IMM_RX.search(d)
        if m and m.group("reg") == reg and val is None:
            return _parse_imm(m.group("imm"))
        m = _ADD_RX.search(d)
        if m and m.group("dst") == reg and val is None:
            base = _parse_imm(m.group("imm"))
            reg = m.group("src")
            continue
        m = _ADRP_RX.search(d)
        if m and m.group("reg") == reg and base is not None:
            return _parse_imm(m.group("imm")) + base
    return None


def recover_register_natives(
    *,
    ops: list[dict],
    call_idx: int,
    resolve_string,
    resolve_qword,
    entry_size: int = 24,
) -> list[RegisterNativesEntry]:
    """Recover JNINativeMethod entries for one RegisterNatives call.

    `ops` is the disasm op list for the enclosing function. `call_idx`
    is the index of the BLR through `*RegisterNatives`. `resolve_string`
    reads a NUL-terminated string at an address; `resolve_qword` reads
    a 64-bit pointer. `entry_size` is sizeof(JNINativeMethod) (24 on
    LP64).
    """
    methods_addr = _track_register_value(ops, "x2", call_idx)
    count = _track_register_value(ops, "x3", call_idx)
    if methods_addr is None or count is None or count <= 0 or count > 1024:
        return []
    out: list[RegisterNativesEntry] = []
    for i in range(count):
        base = methods_addr + i * entry_size
        name_ptr = resolve_qword(base + 0)
        sig_ptr = resolve_qword(base + 8)
        fn_ptr = resolve_qword(base + 16)
        if name_ptr is None or sig_ptr is None or fn_ptr is None:
            continue
        name = resolve_string(name_ptr)
        sig = resolve_string(sig_ptr)
        if not name or not sig:
            continue
        out.append(RegisterNativesEntry(
            method_name=name, signature=sig, fn_addr=hex(fn_ptr),
        ))
    return out
