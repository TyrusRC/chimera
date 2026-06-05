"""Tests for the multi-heuristic diff mode and BinDiff CSV export.

Three contracts under test:
  1. The BinDiff CSV round-trips: what `export_bindiff_csv` writes is
     exactly what `parse_bindiff_csv` reads back.
  2. `heuristic="multi"` produces a score in [0, 1] and is configurable
     via the `weights=` kwarg.
  3. The default `diff_models()` call is bit-identical to the legacy
     pipeline when neither new flag is set.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest


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


# ---------- BinDiff CSV export ------------------------------------------


def test_bindiff_csv_round_trips_via_parser():
    from chimera.diff.bindiff_export import (
        BINDIFF_CSV_HEADER,
        export_bindiff_csv,
        parse_bindiff_csv,
    )
    result = {
        "matched": [
            {"a_address": "0x1000", "b_address": "0x2000",
             "a_name": "encode", "b_name": "encode",
             "similarity": 0.97, "fingerprint": "disasm"},
        ],
        "changed": [
            {"a_address": "0x1100", "b_address": "0x2100",
             "a_name": "decode", "b_name": "decode",
             "similarity": 0.55, "fingerprint": "decomp"},
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bindiff.csv"
        n = export_bindiff_csv(result, path)
        assert n == 2
        text = path.read_text()
        assert ",".join(BINDIFF_CSV_HEADER) in text
        rows = parse_bindiff_csv(path)
    assert len(rows) == 2
    by_a = {r["addr_a"]: r for r in rows}
    assert by_a["0x1000"]["similarity"] == pytest.approx(0.97, abs=1e-4)
    # disasm fingerprint → high confidence; decomp → lower.
    assert by_a["0x1000"]["confidence"] > by_a["0x1100"]["confidence"]
    assert by_a["0x1000"]["name_a"] == "encode"


def test_bindiff_csv_skips_rows_with_missing_addresses():
    from chimera.diff.bindiff_export import export_bindiff_csv, parse_bindiff_csv
    result = {
        "matched": [
            {"a_address": "0x1", "b_address": "0x2",
             "a_name": "x", "b_name": "x",
             "similarity": 0.9, "fingerprint": "disasm"},
            {"a_address": "0x1", "b_address": "",
             "a_name": "broken", "b_name": "",
             "similarity": 0.0, "fingerprint": "name"},
        ],
        "changed": [],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "out.csv"
        n = export_bindiff_csv(result, path)
        rows = parse_bindiff_csv(path)
    assert n == 1
    assert len(rows) == 1
    assert rows[0]["addr_a"] == "0x1"


# ---------- multi-heuristic mode ----------------------------------------


def test_multi_heuristic_score_is_in_unit_interval():
    from chimera.diff.function_similarity import diff_iterables
    a = [_F("0x1000", "encode",
            disassembly=_disasm(["mov", "add", "sub", "ret"] * 4))]
    b = [_F("0x2000", "encode",
            disassembly=_disasm(["mov", "add", "sub", "ret"] * 4))]
    r = diff_iterables(a, b, heuristic="multi")
    assert r["heuristic"] == "multi"
    sim = r["matched"][0]["similarity"]
    assert 0.0 <= sim <= 1.0
    # Identical functions in identical roles should saturate to 1.0.
    assert sim == pytest.approx(1.0, abs=1e-3)


def test_multi_heuristic_weights_are_configurable():
    from chimera.diff.function_similarity import diff_iterables
    # Drifted body but overlapping opcode bag. Shingle Jaccard sees little
    # to no overlap (4-grams don't recur) but the mnemonic histogram
    # cosine is near-perfect. Pick streams whose 4-gram sets are disjoint.
    mnems_a = ["mov", "mov", "mov", "add", "add", "sub", "sub", "ret"]
    mnems_b = ["sub", "sub", "ret", "mov", "add", "mov", "add", "mov"]
    a = [_F("0x1000", "f", disassembly=_disasm(mnems_a))]
    b = [_F("0x2000", "f", disassembly=_disasm(mnems_b))]
    r_jac_heavy = diff_iterables(a, b, heuristic="multi",
                                 weights={"jaccard": 1.0, "cg": 0.0,
                                          "bb": 0.0, "mnemonic": 0.0})
    r_mn_heavy = diff_iterables(a, b, heuristic="multi",
                                weights={"jaccard": 0.0, "cg": 0.0,
                                         "bb": 0.0, "mnemonic": 1.0})
    sim_jac = (r_jac_heavy["matched"] + r_jac_heavy["changed"])[0]["similarity"]
    sim_mn = (r_mn_heavy["matched"] + r_mn_heavy["changed"])[0]["similarity"]
    # Mnemonic cosine ignores order → near-perfect. Jaccard-only sees zero
    # shingle overlap with the staggered window → much lower.
    assert sim_mn > sim_jac


def test_multi_heuristic_empty_weights_falls_back_to_default():
    from chimera.diff.function_similarity import diff_iterables
    a = [_F("0x1", "f", disassembly=_disasm(["mov", "ret"] * 5))]
    b = [_F("0x2", "f", disassembly=_disasm(["mov", "ret"] * 5))]
    # All-zero weights would produce a NaN if we naively normalised;
    # implementation must fall back to defaults instead.
    r = diff_iterables(a, b, heuristic="multi",
                       weights={"jaccard": 0.0, "cg": 0.0,
                                "bb": 0.0, "mnemonic": 0.0})
    sim = (r["matched"] + r["changed"])[0]["similarity"]
    assert 0.0 <= sim <= 1.0


def test_unknown_heuristic_raises_clear_error():
    from chimera.diff.function_similarity import diff_iterables
    with pytest.raises(ValueError) as exc:
        diff_iterables([_F("0x1", "f")], [_F("0x2", "f")], heuristic="bogus")
    assert "heuristic" in str(exc.value).lower()


# ---------- default behaviour unchanged ---------------------------------


def test_default_diff_unchanged_when_no_new_flags_set():
    """When neither `heuristic="multi"` nor `--export-bindiff` is set, the
    diff result must be identical to the legacy Jaccard output."""
    from chimera.diff.function_similarity import diff_iterables
    mnems = ["mov", "add", "sub", "ret"] * 5
    a = [_F("0x1000", "f", disassembly=_disasm(mnems))]
    b = [_F("0x2000", "f", disassembly=_disasm(mnems))]
    r = diff_iterables(a, b)
    # No `heuristic`/`weights`/`rerank` keys in the result by default —
    # preserves the pre-existing shape.
    assert "heuristic" not in r
    assert "weights" not in r
    assert "rerank" not in r
    assert r["totals"]["matched"] == 1
    assert r["matched"][0]["similarity"] == pytest.approx(1.0)
