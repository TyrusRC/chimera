"""Heuristic OLLVM-style obfuscation detector over r2 CFG output.

Looks for the three signature transformations from the original OLLVM
paper (and most commercial OLLVM-derived obfuscators like Hikari, Promon,
DexProtector native, Appdome, Verimatrix):

* **Control-flow flattening (CFF)**: a single dispatcher block fans out
  to every other block of the function via a switch on a state variable.
  We flag a function as CFF when (a) its block count is high, (b) the
  most-incoming-edges block dwarfs the rest, and (c) that dispatcher
  reads a small set of registers and switches.
* **Bogus control flow (BCF)**: opaque-predicate branches duplicate the
  block count without changing semantics. We flag when block count is
  much larger than instruction count would predict.
* **Instruction substitution (ISUB)**: arithmetic identities expand a
  single op into a chain. We flag when the instruction-to-block ratio is
  abnormally high *and* arithmetic ops dominate.

These are heuristics — they false-positive on giant hand-written state
machines and false-negative on aggressively merged dispatchers. Use
hits as a hint to invoke deeper deobfuscation, not as ground truth.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger(__name__)


@dataclass
class OllvmFinding:
    function: str
    address: str
    technique: str          # ollvm_cff | ollvm_bcf | ollvm_isub
    score: float            # 0.0 - 1.0
    detail: str


# Heuristic thresholds. Tuned on a small set of hand-checked OLLVM samples
# (including Hikari and DexProtector native shims). Tweak via callers'
# arguments if false-positive rates show up on a real corpus.
# Tuned to reject natural dispatcher functions (e.g. JNI_OnLoad, jump
# tables) which look superficially like CFF/BCF. Real OLLVM-protected
# functions tend to have order-of-magnitude more blocks and lower
# instructions-per-block ratios than what these thresholds permit.
_CFF_MIN_BLOCKS = 30
_CFF_DISPATCHER_INDEGREE_RATIO = 0.40   # dispatcher must absorb >=40% of edges
_BCF_MIN_BLOCKS = 40
_BCF_INSN_PER_BLOCK_MAX = 3.5           # very small blocks => suspicious
_ISUB_ARITH_RATIO = 0.55                # >=55% of ops are add/sub/xor/and/or
_ISUB_INSN_PER_BLOCK_MIN = 8.0


_ARITH_OPS = {
    "add", "sub", "eor", "orr", "and", "lsl", "lsr", "asr",
    "mul", "udiv", "sdiv", "neg",
}


def detect_ollvm_in_disasm(
    per_function_disasm: dict[str, dict],
) -> list[OllvmFinding]:
    """Run heuristics over r2's `triage_with_disasm` per-function output.

    `per_function_disasm` is the dict shape r2pipe returns from `pdfj`
    walked over every FUNC symbol — keyed by hex offset, value
    `{name, ops}` where each op is a normalized dict.
    """
    findings: list[OllvmFinding] = []
    for offset_hex, body in per_function_disasm.items():
        ops: list[dict[str, Any]] = body.get("ops") or []
        if not ops:
            continue
        name = body.get("name") or offset_hex

        blocks = _split_into_blocks(ops)
        n_blocks = len(blocks)
        n_ops = len(ops)
        if n_blocks < 4:
            continue

        # CFF: dispatcher dominance.
        indeg = _block_indegrees(blocks)
        if n_blocks >= _CFF_MIN_BLOCKS and indeg:
            top = max(indeg.values())
            total_edges = sum(indeg.values()) or 1
            ratio = top / total_edges
            if ratio >= _CFF_DISPATCHER_INDEGREE_RATIO:
                findings.append(OllvmFinding(
                    function=name, address=offset_hex,
                    technique="ollvm_cff",
                    score=min(1.0, ratio + 0.1),
                    detail=f"dispatcher absorbs {ratio:.0%} of edges, "
                           f"{n_blocks} blocks",
                ))

        # BCF: many tiny blocks.
        ratio_ipb = n_ops / n_blocks
        if n_blocks >= _BCF_MIN_BLOCKS and ratio_ipb <= _BCF_INSN_PER_BLOCK_MAX:
            findings.append(OllvmFinding(
                function=name, address=offset_hex,
                technique="ollvm_bcf",
                score=min(1.0, 0.5 + (1.0 - ratio_ipb / _BCF_INSN_PER_BLOCK_MAX) / 2),
                detail=f"{n_blocks} blocks averaging {ratio_ipb:.1f} insn/block",
            ))

        # ISUB: arithmetic-heavy expansion.
        arith = sum(1 for op in ops if op.get("opcode", "") in _ARITH_OPS)
        if n_ops >= 50 and arith / n_ops >= _ISUB_ARITH_RATIO and \
                ratio_ipb >= _ISUB_INSN_PER_BLOCK_MIN:
            findings.append(OllvmFinding(
                function=name, address=offset_hex,
                technique="ollvm_isub",
                score=arith / n_ops,
                detail=f"{arith}/{n_ops} arithmetic ops, "
                       f"{ratio_ipb:.1f} insn/block",
            ))

    return findings


def _split_into_blocks(ops: list[dict]) -> list[list[dict]]:
    """Split a flat op list into blocks at branch-targets and after branches."""
    if not ops:
        return []
    target_offsets = _branch_targets(ops)
    blocks: list[list[dict]] = []
    current: list[dict] = []
    for op in ops:
        if op.get("offset") in target_offsets and current:
            blocks.append(current)
            current = []
        current.append(op)
        if _is_branch(op):
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def _branch_targets(ops: Iterable[dict]) -> set[int]:
    out: set[int] = set()
    for op in ops:
        if not _is_branch(op):
            continue
        for operand in op.get("operands") or []:
            if isinstance(operand, int):
                out.add(operand)
    return out


def _is_branch(op: dict) -> bool:
    opcode = (op.get("opcode") or "").lower()
    return opcode in ("b", "br", "bl", "blr", "ret") or opcode.startswith("b.") \
        or opcode.startswith("cb") or opcode.startswith("tb")


def _block_indegrees(blocks: list[list[dict]]) -> dict[int, int]:
    """For each block (keyed by its first op's offset), count incoming edges."""
    if not blocks:
        return {}
    block_starts = {b[0].get("offset"): i for i, b in enumerate(blocks) if b}
    indeg: dict[int, int] = {b[0].get("offset"): 0 for b in blocks if b}
    for i, block in enumerate(blocks):
        if not block:
            continue
        last = block[-1]
        if _is_branch(last):
            for operand in last.get("operands") or []:
                if isinstance(operand, int) and operand in indeg:
                    indeg[operand] += 1
        # Fallthrough into the next block.
        if i + 1 < len(blocks):
            nxt_offset = blocks[i + 1][0].get("offset")
            if nxt_offset in indeg:
                indeg[nxt_offset] += 1
    return indeg


def summarize(findings: list[OllvmFinding]) -> dict[str, int]:
    """Group findings by technique → hit count."""
    out: dict[str, int] = {}
    for f in findings:
        out[f.technique] = out.get(f.technique, 0) + 1
    return out
