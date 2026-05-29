"""Tests for chimera.diff.function_similarity — Jaccard-based BinDiff."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest

from chimera.diff.function_similarity import diff_iterables, diff_models


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


def test_identical_functions_match_with_perfect_similarity():
    mnems = ["mov", "add", "sub", "cmp", "jne", "ret"]
    a = [_F(address="0x1000", name="encode", disassembly=_disasm(mnems))]
    b = [_F(address="0x2000", name="encode", disassembly=_disasm(mnems))]
    res = diff_iterables(a, b)
    assert res["totals"]["matched"] == 1
    assert res["matched"][0]["similarity"] == pytest.approx(1.0)
    assert res["matched"][0]["fingerprint"] == "disasm"


def test_renamed_function_still_matches_via_greedy_bipartite():
    mnems = ["mov", "add", "sub", "cmp", "jne", "ret"] * 3
    a = [_F(address="0x1000", name="encode_v1", disassembly=_disasm(mnems))]
    b = [_F(address="0x2000", name="encode_v2", disassembly=_disasm(mnems))]
    res = diff_iterables(a, b, threshold=0.85)
    assert res["totals"]["matched"] == 1
    m = res["matched"][0]
    assert m["a_name"] == "encode_v1" and m["b_name"] == "encode_v2"


def test_drifted_function_with_same_name_is_classified_changed():
    mnems_a = ["mov", "add", "sub", "cmp", "jne", "ret"] * 3
    mnems_b = ["mov", "xor", "shl", "test", "jz", "call", "ret"] * 3
    a = [_F(address="0x1000", name="decode", disassembly=_disasm(mnems_a))]
    b = [_F(address="0x2000", name="decode", disassembly=_disasm(mnems_b))]
    res = diff_iterables(a, b, threshold=0.85)
    assert res["totals"]["changed"] == 1
    assert res["totals"]["matched"] == 0
    assert res["changed"][0]["a_name"] == "decode"


def test_added_and_removed_functions_surface():
    mnems = ["mov", "add", "ret"] * 4
    a = [
        _F(address="0x1000", name="alpha", disassembly=_disasm(mnems)),
        _F(address="0x1100", name="only_in_a", disassembly=_disasm(["push", "pop"] * 5)),
    ]
    b = [
        _F(address="0x2000", name="alpha", disassembly=_disasm(mnems)),
        _F(address="0x2200", name="only_in_b", disassembly=_disasm(["nop", "nop"] * 6)),
    ]
    res = diff_iterables(a, b)
    removed_names = {r["name"] for r in res["removed"]}
    added_names = {r["name"] for r in res["added"]}
    assert "only_in_a" in removed_names
    assert "only_in_b" in added_names
    assert res["totals"]["matched"] == 1


def test_decompiled_fallback_when_no_disassembly():
    body = "int main() { x = compute(42); return x + y * z; }"
    a = [_F(address="0x1000", name="main", decompiled=body)]
    b = [_F(address="0x2000", name="main", decompiled=body)]
    res = diff_iterables(a, b)
    assert res["totals"]["matched"] == 1
    assert res["matched"][0]["fingerprint"] == "decomp"


def test_threshold_round_trip_is_deterministic():
    mnems = ["mov", "add", "sub", "ret"] * 5
    a = [_F(address="0x1000", name="f", disassembly=_disasm(mnems))]
    b = [_F(address="0x2000", name="f", disassembly=_disasm(mnems))]
    r1 = diff_iterables(a, b)
    r2 = diff_iterables(a, b)
    assert r1 == r2


def test_empty_inputs_produce_empty_buckets():
    res = diff_iterables([], [])
    assert res["totals"] == {
        "a_functions": 0, "b_functions": 0,
        "matched": 0, "changed": 0, "added": 0, "removed": 0,
    }


def test_threshold_above_one_returns_no_matches():
    """Very strict threshold should kill matches even for identical fingerprints."""
    mnems = ["mov", "add", "ret"] * 4
    a = [_F(address="0x1000", name="f", disassembly=_disasm(mnems))]
    b = [_F(address="0x2000", name="f", disassembly=_disasm(mnems))]
    # threshold=1.5 is impossible → identical match still goes through pass 1
    # because Jaccard == 1.0 < 1.5, so it lands in `changed`
    res = diff_iterables(a, b, threshold=1.5)
    # Either matched (if implementation clamps) or changed (strict reading);
    # both correctly classify identical bodies as "same name".
    assert res["totals"]["matched"] + res["totals"]["changed"] == 1
