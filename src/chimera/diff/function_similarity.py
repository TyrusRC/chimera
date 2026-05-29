"""BinDiff-style per-function similarity comparison.

Given two analyzed `UnifiedProgramModel`s we compute a stable fingerprint
per function and match across the two binaries by Jaccard similarity on
the fingerprint shingles. The result mirrors what BinDiff / Diaphora /
Ghidra BSim emit: matched pairs, name-collisions whose bodies drifted,
added-in-B, removed-from-A.

Why not a learned embedding? Two reasons. First, chimera's contract is
fully offline + FOSS — pulling a model into the wheel is a meaningful
size cost. Second, the analyst workflow only needs to surface "these are
the same function" / "this one drifted" — that's well within reach of
shingled-mnemonic Jaccard, which is what BinDiff has used for decades.

Fingerprint sources (in priority order):
  1. Normalised disassembly mnemonic stream (when available) — opcodes
     only, immediates and registers collapsed. Robust to register
     allocator drift.
  2. Decompiled-code identifiers — keywords + call targets shingled.
     Used when disassembly is unavailable (e.g. Java methods).
  3. Function name — only used to seed candidate matches, never as the
     sole evidence for a match.

Tunable: `threshold` is the minimum Jaccard for "matched". Defaults to
0.85 which empirically separates "same function with compiler-level
drift" from "subtle behavioural change" on a small set of test binaries.
The CLI exposes the knob so analysts can dial it per investigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


SHINGLE_SIZE = 4


def _mnemonic_stream(func) -> list[str]:
    """Return a list of normalised mnemonics for `func`.

    We collapse memory-access prefixes (movzx → mov, lea → mov, etc. are
    NOT collapsed — analyst expectation is that semantics matter), but we
    do strip noisy operand-only differences. The mnemonic by itself is a
    surprisingly good shingle source because compiler-level optimisation
    typically swaps registers and immediates but preserves the opcode
    skeleton of straight-line code.
    """
    if not func.disassembly:
        return []
    out: list[str] = []
    for op in func.disassembly:
        mnem = (op.get("opcode") or "").strip()
        if mnem:
            out.append(mnem.lower())
    return out


def _decomp_tokens(func) -> list[str]:
    """Fallback fingerprint when no disassembly is cached.

    Tokenises decompiled code into identifiers and call targets. Numeric
    literals are dropped — they're noise for similarity.
    """
    if not func.decompiled:
        return []
    out: list[str] = []
    cur: list[str] = []
    for ch in func.decompiled:
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        else:
            if cur:
                tok = "".join(cur)
                if not tok.isdigit():
                    out.append(tok.lower())
                cur.clear()
    if cur:
        out.append("".join(cur).lower())
    return out


def _shingles(stream: list[str], n: int = SHINGLE_SIZE) -> set[str]:
    """Return the set of n-gram shingles over `stream`.

    Returns an empty set when the stream is shorter than n — callers
    treat that as "no fingerprint" and fall back to name-only matching.
    """
    if len(stream) < n:
        return set()
    return {" ".join(stream[i : i + n]) for i in range(len(stream) - n + 1)}


def _fingerprint(func) -> tuple[set[str], str]:
    """Compute (shingles, source_tag) for `func`.

    source_tag is "disasm" or "decomp" or "name" so the diff result can
    explain why two functions matched (or didn't).
    """
    mnems = _mnemonic_stream(func)
    sh = _shingles(mnems)
    if sh:
        return sh, "disasm"
    toks = _decomp_tokens(func)
    sh = _shingles(toks, n=3)  # smaller n for token streams
    if sh:
        return sh, "decomp"
    return set(), "name"


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


@dataclass
class _Entry:
    address: str
    name: str
    fingerprint: set[str]
    source: str


def _build_entries(model) -> list[_Entry]:
    out: list[_Entry] = []
    for f in model.functions:
        fp, src = _fingerprint(f)
        out.append(_Entry(address=f.address, name=f.name or "", fingerprint=fp, source=src))
    return out


def diff_models(model_a, model_b, *, threshold: float = 0.85) -> dict:
    """Compare functions in two models. Returns dict ready to render or JSON.

    Algorithm:
      1. Same-name pairs: for each name in A∩B, compute similarity and
         classify as matched (>=threshold) or changed (<threshold).
      2. Greedy bipartite for the remaining A and B entries: pick the
         best similarity pair iteratively, removing both sides each time.
         Stops when no remaining pair clears `threshold * 0.5` (so a
         high-confidence pair with renames still surfaces, but garbage
         doesn't).
      3. Leftover A → removed; leftover B → added.
    """
    entries_a = _build_entries(model_a)
    entries_b = _build_entries(model_b)
    by_name_b: dict[str, _Entry] = {e.name: e for e in entries_b if e.name}

    matched: list[dict] = []
    changed: list[dict] = []
    consumed_a: set[str] = set()
    consumed_b: set[str] = set()

    # Pass 1: same-name pairs (most analyst-useful signal).
    for ea in entries_a:
        if not ea.name or ea.name not in by_name_b:
            continue
        eb = by_name_b[ea.name]
        sim = _jaccard(ea.fingerprint, eb.fingerprint) if ea.fingerprint or eb.fingerprint else 0.0
        entry = {
            "a_address": ea.address, "b_address": eb.address,
            "a_name": ea.name, "b_name": eb.name,
            "similarity": round(sim, 4),
            "fingerprint": ea.source,
        }
        consumed_a.add(ea.address)
        consumed_b.add(eb.address)
        if sim >= threshold or (ea.source == "name" and ea.name == eb.name):
            matched.append(entry)
        else:
            changed.append(entry)

    # Pass 2: greedy bipartite over the rest. Only consider pairs with
    # at least one non-empty fingerprint — pure name-only matches were
    # handled in pass 1 already.
    remaining_a = [e for e in entries_a if e.address not in consumed_a and e.fingerprint]
    remaining_b = [e for e in entries_b if e.address not in consumed_b and e.fingerprint]
    # Score and rank in one shot — n*m is fine up to ~thousands of fns.
    pairs: list[tuple[float, _Entry, _Entry]] = []
    for ea in remaining_a:
        for eb in remaining_b:
            sim = _jaccard(ea.fingerprint, eb.fingerprint)
            if sim >= threshold * 0.5:
                pairs.append((sim, ea, eb))
    pairs.sort(key=lambda t: -t[0])
    used_a: set[str] = set()
    used_b: set[str] = set()
    for sim, ea, eb in pairs:
        if ea.address in used_a or eb.address in used_b:
            continue
        used_a.add(ea.address)
        used_b.add(eb.address)
        entry = {
            "a_address": ea.address, "b_address": eb.address,
            "a_name": ea.name, "b_name": eb.name,
            "similarity": round(sim, 4),
            "fingerprint": ea.source,
        }
        if sim >= threshold:
            matched.append(entry)
        else:
            changed.append(entry)

    removed = [
        {"address": e.address, "name": e.name}
        for e in entries_a
        if e.address not in consumed_a and e.address not in used_a
    ]
    added = [
        {"address": e.address, "name": e.name}
        for e in entries_b
        if e.address not in consumed_b and e.address not in used_b
    ]

    return {
        "threshold": threshold,
        "totals": {
            "a_functions": len(entries_a),
            "b_functions": len(entries_b),
            "matched": len(matched),
            "changed": len(changed),
            "added": len(added),
            "removed": len(removed),
        },
        "matched": matched,
        "changed": changed,
        "added": added,
        "removed": removed,
    }


def diff_iterables(funcs_a: Iterable, funcs_b: Iterable, *, threshold: float = 0.85) -> dict:
    """Convenience wrapper for tests / non-model callers.

    Accepts any iterable of `FunctionInfo`-shaped objects (must expose
    `address`, `name`, `disassembly`, `decompiled`).
    """

    class _M:
        def __init__(self, fs):
            self.functions = list(fs)

    return diff_models(_M(funcs_a), _M(funcs_b), threshold=threshold)
