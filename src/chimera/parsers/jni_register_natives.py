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
