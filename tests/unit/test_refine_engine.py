"""Tests for the refine-engine registry and the REALTYPE-style eval harness."""

from __future__ import annotations

import json
import os
import shutil

import pytest

from chimera.ai import refine_engine
from chimera.ai.eval import _identifiers, _jaccard, _struct_names, evaluate


def test_default_engines_registered():
    names = refine_engine.list_engines()
    assert "claude" in names
    assert "idioms" in names


def test_get_engine_returns_instance():
    eng = refine_engine.get_engine("claude")
    assert eng.name == "claude"


def test_unknown_engine_raises_valueerror():
    with pytest.raises(ValueError):
        refine_engine.get_engine("does-not-exist")


def test_register_engine_round_trips():
    class _Stub:
        name = "stub-engine"

        def refine(self, pseudo_c, *, function_name="", address=""):
            return refine_engine.RefineResult(code="ok", engine="stub-engine",
                                              raw="ok")

    refine_engine.register_engine("stub-engine", _Stub)
    eng = refine_engine.get_engine("stub-engine")
    result = eng.refine("int x;")
    assert result.code == "ok"
    assert result.engine == "stub-engine"


def test_idioms_engine_errors_without_checkpoint(monkeypatch):
    monkeypatch.delenv("CHIMERA_IDIOMS_CHECKPOINT", raising=False)
    eng = refine_engine.get_engine("idioms")
    with pytest.raises(RuntimeError) as exc:
        eng.refine("int main(){}")
    assert "CHIMERA_IDIOMS_CHECKPOINT" in str(exc.value)


def test_jaccard_basic():
    assert _jaccard(set(), set()) == 1.0
    assert _jaccard({"a"}, set()) == 0.0
    assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert _jaccard({"a", "b"}, {"a", "c"}) == pytest.approx(1 / 3)


def test_identifier_extraction_ignores_short_tokens():
    code = "int foo(int x, int y) { return foo_helper(x); }"
    idents = _identifiers(code)
    assert "foo_helper" in idents
    assert "foo" in idents
    # 'x'/'y' shorter than the 3-char min — should be excluded
    assert "x" not in idents
    assert "y" not in idents


def test_struct_names_picked_up():
    code = "struct aes_ctx ctx; struct ssl_state *s;"
    structs = _struct_names(code)
    assert structs == {"aes_ctx", "ssl_state"}


@pytest.mark.skipif(
    not (shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")),
    reason="no C compiler on PATH",
)
def test_evaluate_perfect_engine_scores_1():
    """If the engine returns the expected output verbatim, all scores hit 1."""
    records = [
        {
            "address": "0x401000",
            "function_name": "fma",
            "decomp_input": "int FUN_401000(){return 0;}",
            "expected": "struct aes_ctx { int state; }; "
                        "int fma_helper(struct aes_ctx *ctx) { return ctx->state; }",
        },
    ]

    def refine(decomp, fname, addr):
        return records[0]["expected"]

    summary = evaluate(records, refine)
    assert summary.total == 1
    assert summary.recompile_rate == pytest.approx(1.0)
    assert summary.mean_identifier_jaccard == pytest.approx(1.0)
    assert summary.mean_struct_recall == pytest.approx(1.0)


def test_evaluate_handles_empty_engine_output(tmp_path):
    records = [{
        "address": "0x1",
        "decomp_input": "FUN_1",
        "expected": "int fma_helper(int x) { return aes_state; }",
    }]
    summary = evaluate(records, lambda d, f, a: "")
    assert summary.total == 1
    # Empty output shouldn't crash; recompile_rate may be 0 or skip on missing
    # compiler, but the harness must always return a summary. With multiple
    # expected identifiers and an empty refined output, jaccard must be 0.
    assert summary.mean_identifier_jaccard == pytest.approx(0.0)
