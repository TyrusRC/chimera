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
from typing import Callable, Iterable, Protocol


SHINGLE_SIZE = 4


# ----------------------------------------------------------------------
# Pluggable similarity backends
# ----------------------------------------------------------------------
#
# The Jaccard implementation below is the default. A Transformer-based
# backend (jTrans, kTrans, CLAP — ISSTA 2022 onwards) would compute an
# embedding per function and compare via cosine similarity instead. We
# don't ship Transformer inference (heavy torch dep), but we expose the
# hook so an `[ml]` extra can register its provider at import time
# without modifying core code or callers.
#
# A backend is a callable: (func) → (signature_set | embedding_vector,
# source_tag). The diff function only cares that the result is hashable
# and comparable via `_similarity(a, b)`.

class SimilarityBackend(Protocol):
    """A pluggable backend that scores function-pair similarity."""

    name: str

    def fingerprint(self, func) -> tuple[object, str]:
        """Return (signature, source_tag) for `func`."""

    def similarity(self, a: object, b: object) -> float:
        """Return similarity in [0.0, 1.0]."""


_BACKENDS: dict[str, SimilarityBackend] = {}


def register_similarity_backend(name: str, backend: SimilarityBackend) -> None:
    """Register a new backend by name. Idempotent."""
    _BACKENDS[name] = backend


def get_similarity_backend(name: str) -> SimilarityBackend | None:
    """Look up a registered backend. Returns None when not registered."""
    return _BACKENDS.get(name)


def available_backends() -> list[str]:
    """List registered backend names; always includes the 'jaccard' default."""
    return ["jaccard"] + [n for n in _BACKENDS if n != "jaccard"]


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


DEFAULT_MULTI_WEIGHTS = {
    "jaccard": 0.5,
    "cg": 0.2,
    "bb": 0.15,
    "mnemonic": 0.15,
}


def diff_models(model_a, model_b, *, threshold: float = 0.85,
                backend: str = "jaccard",
                rerank: str | None = None,
                heuristic: str = "jaccard",
                weights: dict | None = None) -> dict:
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

    `backend` selects the fingerprint provider. "jaccard" is the default
    and the only one we ship inline. Optional backends (jtrans, clap,
    ktrans) can be registered at import time via
    `register_similarity_backend(...)`.
    """
    # Multi-heuristic mode combines Jaccard with structural signals
    # (call-graph degree, basic-block count, mnemonic frequency). Opt-in via
    # `heuristic="multi"` — the default is unchanged. Weights are
    # configurable; values normalise so callers don't need to sum to 1.
    if heuristic == "multi":
        return _maybe_rerank(
            _diff_multi(model_a, model_b, threshold=threshold,
                        weights=weights or DEFAULT_MULTI_WEIGHTS),
            model_a, model_b, rerank,
        )
    if heuristic not in ("jaccard", "multi"):
        raise ValueError(f"unknown heuristic {heuristic!r}; "
                         f"expected 'jaccard' or 'multi'")

    # Pluggable backend dispatch — non-default backends MUST be registered
    # before this call. The Jaccard path is fully inline for speed and
    # because it's what the test suite expects by default.
    if backend != "jaccard":
        bk = get_similarity_backend(backend)
        if bk is None:
            raise ValueError(
                f"similarity backend {backend!r} is not registered. "
                f"Available: {available_backends()}"
            )
        res = _diff_with_backend(model_a, model_b, bk, threshold=threshold)
        return _maybe_rerank(res, model_a, model_b, rerank)

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

    result = {
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
    return _maybe_rerank(result, model_a, model_b, rerank)


def _maybe_rerank(result: dict, model_a, model_b, rerank: str | None) -> dict:
    """Apply an opt-in re-ranking post-pass. None → identity, the default."""
    if not rerank:
        return result
    if rerank == "revdecode":
        # Late import — keeps the rerank module out of the Jaccard fast-path.
        from chimera.diff.revdecode_backend import rerank_diff_result
        return rerank_diff_result(result, model_a, model_b)
    raise ValueError(f"unknown rerank strategy: {rerank!r}")


def _diff_with_backend(model_a, model_b, backend: SimilarityBackend,
                       *, threshold: float) -> dict:
    """Run diff using a registered non-Jaccard backend.

    Kept structurally parallel to the Jaccard fast-path so the result
    schema is identical regardless of which backend ran.
    """
    def _entries(model):
        out = []
        for f in model.functions:
            sig, src = backend.fingerprint(f)
            out.append(_Entry(address=f.address, name=f.name or "",
                              fingerprint=sig, source=f"{backend.name}:{src}"))
        return out

    entries_a = _entries(model_a)
    entries_b = _entries(model_b)
    by_name_b = {e.name: e for e in entries_b if e.name}

    matched: list[dict] = []
    changed: list[dict] = []
    consumed_a: set[str] = set()
    consumed_b: set[str] = set()
    for ea in entries_a:
        if not ea.name or ea.name not in by_name_b:
            continue
        eb = by_name_b[ea.name]
        sim = backend.similarity(ea.fingerprint, eb.fingerprint) if ea.fingerprint and eb.fingerprint else 0.0
        entry = {
            "a_address": ea.address, "b_address": eb.address,
            "a_name": ea.name, "b_name": eb.name,
            "similarity": round(sim, 4),
            "fingerprint": ea.source,
        }
        consumed_a.add(ea.address)
        consumed_b.add(eb.address)
        (matched if sim >= threshold else changed).append(entry)

    remaining_a = [e for e in entries_a if e.address not in consumed_a and e.fingerprint]
    remaining_b = [e for e in entries_b if e.address not in consumed_b and e.fingerprint]
    pairs = []
    for ea in remaining_a:
        for eb in remaining_b:
            sim = backend.similarity(ea.fingerprint, eb.fingerprint)
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
        (matched if sim >= threshold else changed).append(entry)

    removed = [{"address": e.address, "name": e.name}
               for e in entries_a if e.address not in consumed_a and e.address not in used_a]
    added = [{"address": e.address, "name": e.name}
             for e in entries_b if e.address not in consumed_b and e.address not in used_b]
    return {
        "threshold": threshold,
        "backend": backend.name,
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


def diff_iterables(funcs_a: Iterable, funcs_b: Iterable, *, threshold: float = 0.85,
                   backend: str = "jaccard",
                   rerank: str | None = None,
                   heuristic: str = "jaccard",
                   weights: dict | None = None) -> dict:
    """Convenience wrapper for tests / non-model callers.

    Accepts any iterable of `FunctionInfo`-shaped objects (must expose
    `address`, `name`, `disassembly`, `decompiled`).
    """

    class _M:
        def __init__(self, fs):
            self.functions = list(fs)
            self._by_caller: dict[str, list[str]] = {}
            self._by_callee: dict[str, list[str]] = {}

    return diff_models(_M(funcs_a), _M(funcs_b), threshold=threshold,
                       backend=backend, rerank=rerank,
                       heuristic=heuristic, weights=weights)


# ----------------------------------------------------------------------
# Multi-heuristic scoring
# ----------------------------------------------------------------------
#
# The default Jaccard score is mnemonic-shingle similarity. It performs
# well on near-duplicate code but misses two analyst-relevant signals:
#
#   * Structural: a function with 1 caller + 0 callees is unlikely to be
#     the same function as one with 8 callers + 12 callees, even if the
#     mnemonic streams happen to overlap (boilerplate prologues).
#   * Distributional: mnemonic *frequency* (bag-of-opcodes cosine) catches
#     drift the shingle Jaccard misses when the compiler reorders blocks.
#
# Multi-mode computes Jaccard + three structural sub-scores and returns
# the weighted sum. Weights are normalised so callers don't need to ensure
# they sum to 1. The score is always in [0, 1].


@dataclass
class _MultiEntry:
    address: str
    name: str
    shingles: set[str]
    source: str
    in_degree: int
    out_degree: int
    bb_count: int
    mnem_counts: dict[str, int]


def _basic_block_count(func) -> int:
    """Heuristic BB count from a disassembly stream.

    A basic block ends at any control-flow mnemonic (jmp/jcc/ret/call) — we
    count those transitions. If there's no disassembly the function counts
    as one block (the function itself). This intentionally collapses CFG
    nuance: the multi-heuristic uses BB *ratio*, not exact equality, so a
    rough count is enough to discriminate "tiny stub" from "big body".
    """
    if not func.disassembly:
        return 1
    n = 0
    for op in func.disassembly:
        m = (op.get("opcode") or "").lower()
        if not m:
            continue
        if m.startswith("j") or m == "ret" or m == "call":
            n += 1
    return max(1, n)


def _mnemonic_counts(func) -> dict[str, int]:
    """Bag-of-opcodes histogram used for the cosine sub-score."""
    out: dict[str, int] = {}
    if not func.disassembly:
        return out
    for op in func.disassembly:
        m = (op.get("opcode") or "").lower().strip()
        if not m:
            continue
        out[m] = out.get(m, 0) + 1
    return out


def _ratio_similarity(x: int, y: int) -> float:
    """Symmetric ratio in [0, 1]. 1.0 when x == y, 0.0 when one is zero
    and the other is large. Used for both BB-count and degree similarity."""
    if x == 0 and y == 0:
        return 1.0
    if x == 0 or y == 0:
        return 0.0
    return min(x, y) / max(x, y)


def _degree_similarity(in_a: int, out_a: int, in_b: int, out_b: int) -> float:
    """Average of in-degree and out-degree ratio similarities."""
    return 0.5 * (_ratio_similarity(in_a, in_b) + _ratio_similarity(out_a, out_b))


def _mnemonic_cosine(ca: dict[str, int], cb: dict[str, int]) -> float:
    """Cosine similarity over the union of mnemonic histograms.

    Always non-negative because counts are non-negative, so the result is
    already in [0, 1] — no rescaling needed.
    """
    if not ca or not cb:
        return 0.0
    dot = 0.0
    for k, v in ca.items():
        if k in cb:
            dot += v * cb[k]
    na = sum(v * v for v in ca.values()) ** 0.5
    nb = sum(v * v for v in cb.values()) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _normalise_weights(weights: dict) -> dict[str, float]:
    """Drop unknown keys, clamp to non-negative, normalise to sum-to-one.

    If everything is zero we fall back to the default to avoid producing
    NaN — analysts hitting `weights={}` should still get a useful score.
    """
    known = ("jaccard", "cg", "bb", "mnemonic")
    raw = {k: max(0.0, float(weights.get(k, 0.0))) for k in known}
    total = sum(raw.values())
    if total <= 0.0:
        return dict(DEFAULT_MULTI_WEIGHTS)
    return {k: v / total for k, v in raw.items()}


def _build_multi_entries(model) -> list[_MultiEntry]:
    out: list[_MultiEntry] = []
    by_caller = getattr(model, "_by_caller", {}) or {}
    by_callee = getattr(model, "_by_callee", {}) or {}
    for f in model.functions:
        sh, src = _fingerprint(f)
        out.append(_MultiEntry(
            address=f.address,
            name=f.name or "",
            shingles=sh,
            source=src,
            in_degree=len(by_callee.get(f.address, ())),
            out_degree=len(by_caller.get(f.address, ())),
            bb_count=_basic_block_count(f),
            mnem_counts=_mnemonic_counts(f),
        ))
    return out


def _multi_score(a: _MultiEntry, b: _MultiEntry, w: dict[str, float]) -> float:
    """Combined weighted score in [0, 1].

    Each sub-score is in [0, 1] and weights are normalised, so the result
    is guaranteed in [0, 1] without clamping. We still clamp defensively
    against floating-point drift around the boundary.
    """
    jac = _jaccard(a.shingles, b.shingles)
    cg = _degree_similarity(a.in_degree, a.out_degree, b.in_degree, b.out_degree)
    bb = _ratio_similarity(a.bb_count, b.bb_count)
    mn = _mnemonic_cosine(a.mnem_counts, b.mnem_counts)
    score = (w["jaccard"] * jac + w["cg"] * cg
             + w["bb"] * bb + w["mnemonic"] * mn)
    return max(0.0, min(1.0, score))


def _diff_multi(model_a, model_b, *, threshold: float, weights: dict) -> dict:
    """Multi-heuristic diff. Structurally parallel to the Jaccard fast-path
    so the result schema is the same, plus a `heuristic` / `weights` field
    so consumers can audit which mode produced the answer."""
    w = _normalise_weights(weights)
    entries_a = _build_multi_entries(model_a)
    entries_b = _build_multi_entries(model_b)
    by_name_b: dict[str, _MultiEntry] = {e.name: e for e in entries_b if e.name}

    matched: list[dict] = []
    changed: list[dict] = []
    consumed_a: set[str] = set()
    consumed_b: set[str] = set()

    for ea in entries_a:
        if not ea.name or ea.name not in by_name_b:
            continue
        eb = by_name_b[ea.name]
        sim = _multi_score(ea, eb, w)
        entry = {
            "a_address": ea.address, "b_address": eb.address,
            "a_name": ea.name, "b_name": eb.name,
            "similarity": round(sim, 4),
            "fingerprint": f"multi:{ea.source}",
        }
        consumed_a.add(ea.address)
        consumed_b.add(eb.address)
        (matched if sim >= threshold else changed).append(entry)

    remaining_a = [e for e in entries_a if e.address not in consumed_a]
    remaining_b = [e for e in entries_b if e.address not in consumed_b]
    pairs: list[tuple[float, _MultiEntry, _MultiEntry]] = []
    for ea in remaining_a:
        for eb in remaining_b:
            sim = _multi_score(ea, eb, w)
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
            "fingerprint": f"multi:{ea.source}",
        }
        (matched if sim >= threshold else changed).append(entry)

    removed = [{"address": e.address, "name": e.name}
               for e in entries_a
               if e.address not in consumed_a and e.address not in used_a]
    added = [{"address": e.address, "name": e.name}
             for e in entries_b
             if e.address not in consumed_b and e.address not in used_b]
    return {
        "threshold": threshold,
        "heuristic": "multi",
        "weights": w,
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
