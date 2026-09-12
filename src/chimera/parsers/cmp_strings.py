"""Recover a hidden string from a chain of byte comparisons.

A password / serial / key-sequence check is frequently compiled as an unrolled
cascade — ``if (buf[0]=='L') if (buf[1]=='L') if (buf[2]=='U') ...`` — so the
expected value exists ONLY as the immediate operands of a run of ``cmp``
instructions and never appears as a contiguous string in the file. `get_strings`
cannot see it, and FLOSS (`deobfuscate_strings`) recovers strings that are
WRITTEN to memory (stack strings) or emulated/decoded — not comparison targets.
Malware uses the same trick to keep a command word or magic out of `strings`.

This linearly disassembles a function (arch-aware, so 32-bit targets work — the
model's x64 disasm path does not), collects the printable-ASCII bytes compared
against byte-sized operands in address order, and groups nearby comparisons into
candidate strings. It reads the LAST operand token, so a displacement inside a
memory operand (`cmp byte [eax + 0x4c], bl`) is never mistaken for the compared
value, and non-printable immediates (length checks like `cmp eax, 0xf`) are
filtered out.

Driving example: Flare-On "Magic 8 Ball" gates on the arrow-key sequence
"LLURULDUL", present only as ``cmp byte [buf+i], 'L'/'U'/'R'/'D'`` immediates.

NOTE: a heuristic — it reports candidates ranked by length; the analyst picks the
obvious one. It follows the linear byte stream from `va`, not the control-flow
graph, so a cascade split across non-contiguous blocks may segment; raise
`gap`/`max_bytes` if a known sequence comes back split.
"""
from __future__ import annotations

import re

from chimera.patching.binary_patcher import BinaryPatcher, PatchError
from chimera.patching.disasm import DisasmError, make_cs

_IMM_TOKEN = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)\Z")


def _last_immediate(op_str: str) -> int | None:
    """Value of the trailing immediate operand, or None if the last operand
    is a register/memory reference (so a memory displacement is never read)."""
    if not op_str:
        return None
    tok = op_str.rsplit(",", 1)[-1].strip()
    if _IMM_TOKEN.fullmatch(tok):
        try:
            return int(tok, 0)
        except ValueError:
            return None
    return None


def recover_compare_string(path, va, *, max_bytes: int = 2048, min_run: int = 4,
                           gap: int = 128, mnemonics=("cmp",)) -> dict:
    """Reconstruct the string(s) implied by a byte-comparison cascade at `va`.

    Disassembles up to `max_bytes` of code from `va`, collects printable-ASCII
    ``cmp``-immediates in address order, and segments them into candidate strings
    (a gap > `gap` bytes between consecutive comparisons starts a new candidate).
    Only candidates of at least `min_run` characters are returned.
    """
    try:
        p = BinaryPatcher.open(path)
    except PatchError as exc:
        return {"available": True, "error": str(exc)}
    arch = p.machine_arch()
    if arch is None:
        return {"available": True, "error": "could not detect the binary's architecture"}
    try:
        code = p.read(int(va), max_bytes)
    except PatchError as exc:
        return {"available": True, "error": f"VA {int(va):#x}: {exc}"}
    try:
        md = make_cs(arch)
    except DisasmError as exc:
        return {"available": False, "error": str(exc)}

    want = set(mnemonics)
    hits: list[tuple[int, str]] = []
    for insn in md.disasm(bytes(code), int(va)):
        if insn.mnemonic in want:
            imm = _last_immediate(insn.op_str)
            if imm is not None and 0x20 <= imm <= 0x7E:
                hits.append((insn.address, chr(imm)))

    runs: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] = []
    for addr, ch in hits:
        if cur and addr - cur[-1][0] > gap:
            runs.append(cur)
            cur = []
        cur.append((addr, ch))
    if cur:
        runs.append(cur)

    candidates = [
        {"string": "".join(c for _, c in r), "start_va": hex(r[0][0]), "count": len(r),
         "chars": [{"va": hex(a), "char": c} for a, c in r]}
        for r in runs if len(r) >= min_run
    ]
    candidates.sort(key=lambda c: c["count"], reverse=True)
    return {
        "available": True, "arch": arch, "function_va": hex(int(va)),
        "candidates": candidates,
        "note": ("strings reconstructed from cmp-immediate cascades — get_strings "
                 "and FLOSS miss these (never contiguous in the file). Enter the "
                 "longest candidate as the expected input / key sequence."),
    }
