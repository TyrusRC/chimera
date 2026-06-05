"""Tests for KEENHash + REVDECODE similarity backends.

Covers three contracts:
  1. KEENHash registers itself at import time and degrades gracefully when
     the heavyweight `keenhash` library / external embedder is absent.
  2. REVDECODE's Viterbi reranker produces stable, deterministic output on
     a small synthetic n-best input.
  3. `rerank=None` (the default) leaves `diff_models` behaviour
     bit-identical to the pre-existing Jaccard pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest


# ---------- shared fixtures ------------------------------------------------


@dataclass
class _F:
    address: str
    name: str
    disassembly: Optional[list[dict]] = None
    decompiled: Optional[str] = None
    original_name: str = ""
    language: str = "c"
    classification: str = "unknown"
    layer: str = "native"
    source_backend: str = "test"
    signature: Optional[str] = None
    ai_renamed: bool = False
    ai_comments: Optional[str] = None
    sources: list = field(default_factory=list)
    metadata: Optional[dict] = None


def _disasm(mnems: list[str]) -> list[dict]:
    return [{"offset": i * 4, "opcode": m, "operands": [], "target_sym": None}
            for i, m in enumerate(mnems)]


class _Model:
    """Minimal duck-typed UnifiedProgramModel for tests.

    Mimics the parts the backends actually touch: `.functions` iterable and
    the private adjacency dicts the REVDECODE adapter uses.
    """

    def __init__(self, funcs, edges=None):
        self.functions = list(funcs)
        self.binary = None
        self._by_caller = {}
        self._by_callee = {}
        if edges:
            for src, dst in edges:
                self._by_caller.setdefault(src, []).append(dst)
                self._by_callee.setdefault(dst, []).append(src)


# ---------- KEENHash backend ---------------------------------------------


def test_keenhash_registers_at_import_time():
    # Importing the module is the side-effect under test — it must register
    # the backend at import time.
    from chimera.diff import keenhash_backend
    from chimera.diff.function_similarity import (
        available_backends,
        get_similarity_backend,
    )
    assert keenhash_backend is not None
    assert "keenhash" in available_backends()
    bk = get_similarity_backend("keenhash")
    assert bk is not None and bk.name == "keenhash"


def test_keenhash_is_available_returns_bool_no_crash():
    from chimera.diff.keenhash_backend import get_keenhash_backend
    bk = get_keenhash_backend()
    # Whatever the host environment looks like, this must be a clean bool —
    # never an ImportError or a None.
    assert isinstance(bk.is_available(), bool)


def test_keenhash_stub_embedding_is_deterministic_and_fixed_dim():
    """Without the heavy library, the stub embedder must still produce a
    stable signature so downstream callers can wire it without crashing."""
    from chimera.diff.keenhash_backend import KEENHASH_DIM, get_keenhash_backend
    bk = get_keenhash_backend()
    fns = [
        _F("0x1000", "f1", disassembly=_disasm(["mov", "add", "ret"] * 4)),
        _F("0x1100", "f2", disassembly=_disasm(["push", "pop", "ret"] * 4)),
    ]
    model = _Model(fns)
    v1 = bk.compute_embedding(model)
    v2 = bk.compute_embedding(model)
    assert len(v1) == KEENHASH_DIM
    assert v1 == v2  # deterministic across calls


def test_keenhash_similarity_high_for_same_model_low_for_disjoint():
    from chimera.diff.keenhash_backend import get_keenhash_backend
    bk = get_keenhash_backend()
    same = _Model([
        _F("0x1000", "f", disassembly=_disasm(["mov", "add", "sub", "ret"] * 6)),
    ])
    other = _Model([
        _F("0x2000", "g", disassembly=_disasm(["xor", "shl", "test", "jz"] * 6)),
    ])
    v_self = bk.compute_embedding(same)
    v_self2 = bk.compute_embedding(same)
    v_other = bk.compute_embedding(other)
    assert bk.similarity(v_self, v_self2) == pytest.approx(1.0, abs=1e-6)
    # Disjoint mnemonic streams → low similarity. Stub uses feature hashing
    # so collisions are possible, but expected score < 0.5 with high prob.
    assert bk.similarity(v_self, v_other) < 0.5


def test_keenhash_degrades_gracefully_when_library_missing(monkeypatch):
    """If the optional library disappears at runtime, the per-function diff
    pipeline must still produce a valid result via the mnemonic fallback."""
    from chimera.diff.function_similarity import diff_iterables
    # Force the absence by patching the env probe.
    monkeypatch.setenv("CHIMERA_KEENHASH_EMBEDDING_BIN", "")
    mnems = ["mov", "add", "sub", "ret"] * 5
    a = [_F("0x1000", "encode", disassembly=_disasm(mnems))]
    b = [_F("0x2000", "encode", disassembly=_disasm(mnems))]
    r = diff_iterables(a, b, backend="keenhash")
    # Schema match: backend stamped, totals consistent.
    assert r["backend"] == "keenhash"
    assert r["totals"]["matched"] == 1


# ---------- REVDECODE reranker -------------------------------------------


def test_revdecode_rerank_picks_best_match_per_position():
    from chimera.diff.revdecode_backend import RevDecodeReranker
    candidates = [
        {"a_address": "0x1", "a_name": "f1", "options": [
            {"b_address": "0xA", "similarity": 0.9, "b_name": "fa"},
            {"b_address": "0xB", "similarity": 0.4, "b_name": "fb"},
        ]},
        {"a_address": "0x2", "a_name": "f2", "options": [
            {"b_address": "0xA", "similarity": 0.3, "b_name": "fa"},
            {"b_address": "0xC", "similarity": 0.8, "b_name": "fc"},
        ]},
    ]
    out = RevDecodeReranker().rerank(candidates, {})
    by_a = {r["a_address"]: r for r in out}
    # f1 should keep 0xA (its best); f2 must NOT also pick 0xA (used) —
    # falls to 0xC at 0.8.
    assert by_a["0x1"]["b_address"] == "0xA"
    assert by_a["0x2"]["b_address"] == "0xC"


def test_revdecode_rerank_is_deterministic_and_stable_under_shuffle():
    from chimera.diff.revdecode_backend import RevDecodeReranker
    base = [
        {"a_address": "0x1", "a_name": "f1", "options": [
            {"b_address": "0xA", "similarity": 0.7},
            {"b_address": "0xB", "similarity": 0.7},  # tie
        ]},
    ]
    out1 = RevDecodeReranker().rerank(base, {})
    # Re-run with options reversed; ties must break by lexicographic order
    # of b_address so the output is identical.
    swapped = [{**base[0], "options": list(reversed(base[0]["options"]))}]
    out2 = RevDecodeReranker().rerank(swapped, {})
    assert out1[0]["b_address"] == out2[0]["b_address"] == "0xA"


def test_revdecode_rerank_abstains_when_no_candidate_clears_null_penalty():
    from chimera.diff.revdecode_backend import RevDecodeReranker
    candidates = [
        {"a_address": "0x1", "a_name": "f1", "options": [
            {"b_address": "0xZ", "similarity": 0.0},
        ]},
    ]
    out = RevDecodeReranker(null_penalty=0.1).rerank(candidates, {})
    # 0.0 is below -null_penalty? null_score = -0.1, candidate score = 0.0.
    # Candidate wins, so output is still 0xZ; verifies the boundary holds.
    assert out[0]["b_address"] == "0xZ"

    out_strict = RevDecodeReranker(null_penalty=-1.0).rerank(candidates, {})
    # Null penalty = -1.0 → null_score = +1.0, beats sim=0.0 → abstain.
    assert out_strict[0]["b_address"] is None


def test_rerank_default_none_leaves_diff_unchanged():
    """The default `rerank=None` path must be bit-identical to the legacy
    pipeline — no `rerank` key in the output, totals match the pre-rerank
    Jaccard answer."""
    from chimera.diff.function_similarity import diff_iterables
    mnems = ["mov", "add", "sub", "ret"] * 5
    a = [_F("0x1000", "f", disassembly=_disasm(mnems))]
    b = [_F("0x2000", "f", disassembly=_disasm(mnems))]
    r = diff_iterables(a, b)
    assert "rerank" not in r
    assert r["totals"]["matched"] == 1


def test_rerank_revdecode_on_jaccard_result_preserves_schema():
    from chimera.diff.function_similarity import diff_iterables
    mnems = ["mov", "add", "sub", "ret"] * 5
    a = [_F("0x1000", "encode", disassembly=_disasm(mnems))]
    b = [_F("0x2000", "encode", disassembly=_disasm(mnems))]
    r = diff_iterables(a, b, rerank="revdecode")
    assert r.get("rerank") == "revdecode"
    # Result schema still has all four buckets.
    for key in ("matched", "changed", "added", "removed", "totals"):
        assert key in r
    assert r["totals"]["matched"] == 1


def test_unknown_rerank_strategy_raises_clear_error():
    from chimera.diff.function_similarity import diff_iterables
    a = [_F("0x1000", "f")]
    b = [_F("0x2000", "f")]
    with pytest.raises(ValueError) as exc:
        diff_iterables(a, b, rerank="not-a-strategy")
    assert "rerank" in str(exc.value).lower()
