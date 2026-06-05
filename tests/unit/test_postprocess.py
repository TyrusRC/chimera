"""Tests for the msynth-style and PseudoFix-style post-processors."""

from __future__ import annotations

from chimera.ai.postprocess import (
    apply_postprocess,
    refactor_structure,
    simplify_mba,
)


# ----------------------------------------------------------------------
# simplify_mba — positive and negative for each rule
# ----------------------------------------------------------------------


def test_simplify_xor_self_to_zero():
    assert simplify_mba("z = x ^ x;") == "z = 0;"


def test_simplify_xor_self_negative_different_names():
    # x ^ y must not collapse — different tokens.
    src = "z = x ^ y;"
    assert simplify_mba(src) == src


def test_simplify_and_zero():
    assert simplify_mba("z = x & 0;") == "z = 0;"
    assert simplify_mba("z = 0 & x;") == "z = 0;"


def test_simplify_and_zero_negative_does_not_touch_nonzero_or_hex():
    # x & 1 must stay; "0x" must not be mis-eaten by the `& 0` rule.
    assert simplify_mba("z = x & 1;") == "z = x & 1;"
    assert simplify_mba("z = x & 0xFF;") == "z = x & 0xFF;"


def test_simplify_or_zero():
    assert simplify_mba("z = x | 0;") == "z = x;"
    assert simplify_mba("z = 0 | x;") == "z = x;"


def test_simplify_or_zero_negative():
    assert simplify_mba("z = x | 1;") == "z = x | 1;"


def test_simplify_and_not_zero():
    assert simplify_mba("z = x & ~0;") == "z = x;"
    assert simplify_mba("z = ~0 & x;") == "z = x;"


def test_simplify_and_not_zero_negative():
    # ~1 mask must stay alone.
    assert simplify_mba("z = x & ~1;") == "z = x & ~1;"


def test_simplify_xor_xor_collapse():
    # (a ^ b) ^ a -> b
    assert simplify_mba("z = (a ^ b) ^ a;") == "z = b;"
    # (a ^ b) ^ b -> a
    assert simplify_mba("z = (a ^ b) ^ b;") == "z = a;"


def test_simplify_xor_xor_negative():
    # Distinct third operand must not collapse.
    src = "z = (a ^ b) ^ c;"
    assert simplify_mba(src) == src


def test_simplify_mba_is_idempotent():
    src = "z = (x ^ x) | 0;"
    once = simplify_mba(src)
    twice = simplify_mba(once)
    assert once == twice
    assert once == "z = 0;"


# ----------------------------------------------------------------------
# refactor_structure — positive and negative
# ----------------------------------------------------------------------


def test_if_return_return_collapses_to_ternary():
    src = "if (cond) { return 1; } return 0;"
    out = refactor_structure(src)
    assert out == "return cond ? 1 : 0;"


def test_if_return_return_negative_when_body_has_side_effect():
    # Body is not a single return — must not be rewritten.
    src = "if (cond) { do_thing(); return 1; } return 0;"
    assert refactor_structure(src) == src


def test_goto_dead_removal():
    src = "goto END; END: return 0;"
    out = refactor_structure(src)
    assert "goto END;" not in out
    assert "END:" in out  # label preserved
    assert "return 0;" in out


def test_goto_dead_negative_when_target_differs():
    src = "goto A; B: return 0;"
    # Labels differ — rule must not fire.
    assert refactor_structure(src) == src


def test_dowhile0_unwrap():
    src = "do { x = 1; } while (0);"
    out = refactor_structure(src)
    assert out.strip() == "x = 1;"


def test_dowhile0_negative_when_condition_is_nonzero():
    src = "do { x = 1; } while (1);"
    assert refactor_structure(src) == src


def test_refactor_structure_preserves_unrelated_text():
    src = "int main(void) { return 0; }"
    assert refactor_structure(src) == src


# ----------------------------------------------------------------------
# apply_postprocess — orchestrator
# ----------------------------------------------------------------------


def test_apply_postprocess_composes_both_pipelines():
    # MBA simplification + structural collapse in one call.
    src = "if (flag) { return x ^ x; } return y | 0;"
    out = apply_postprocess(src)
    assert out == "return flag ? 0 : y;"


def test_apply_postprocess_can_disable_mba():
    src = "z = x ^ x;"
    out = apply_postprocess(src, mba=False, structure=True)
    assert out == src  # MBA rule did not run


def test_apply_postprocess_can_disable_structure():
    src = "if (c) { return 1; } return 0;"
    out = apply_postprocess(src, mba=True, structure=False)
    assert out == src


def test_apply_postprocess_noop_when_both_off():
    src = "z = x ^ x;"
    assert apply_postprocess(src, mba=False, structure=False) == src
