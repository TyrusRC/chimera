"""Tests for carrying annotations across binary versions."""
from __future__ import annotations

from pathlib import Path

from chimera.core.overlay import ProjectOverlay
from chimera.diff.overlay_propagate import apply_plan, build_plan


def _overlay(tmp_path, sha) -> ProjectOverlay:
    return ProjectOverlay(sha256=sha, _path=Path(tmp_path) / sha / "overlay.json")


def test_high_similarity_pair_carries_all_annotation_kinds(tmp_path):
    a = _overlay(tmp_path, "a" * 64)
    a.rename_function("0x1000", "decode_license")
    a.set_function_type("0x1000", "int decode_license(char*)")
    a.set_classification("0x1000", "license_check")
    a.add_comment("0x1000", 0, "entry")
    a.rename_variable("0x1000", "iVar1", "key_byte")

    matched = [{"a_address": "0x1000", "b_address": "0x2000", "similarity": 0.97}]
    plan = build_plan(a, matched, min_similarity=0.85)
    assert plan.summary()["carried"] == 1
    c = plan.carried[0]
    assert c.b_address == "0x2000" and c.name == "decode_license"
    assert c.signature and c.classification == "license_check"
    assert c.comments["0"] == "entry" and c.variables["iVar1"] == "key_byte"

    b = _overlay(tmp_path, "b" * 64)
    assert apply_plan(plan, b) == 1
    assert b.get_function_name("0x2000") == "decode_license"
    assert b.get_function_type("0x2000") == "int decode_license(char*)"
    assert b.user_classifications["0x2000"] == "license_check"
    assert b.get_comments("0x2000")["0"] == "entry"
    assert b.get_variable_renames("0x2000")["iVar1"] == "key_byte"


def test_low_similarity_pair_is_skipped_not_carried(tmp_path):
    a = _overlay(tmp_path, "a" * 64)
    a.rename_function("0x1000", "drifted")
    matched = [{"a_address": "0x1000", "b_address": "0x2000", "similarity": 0.40}]
    plan = build_plan(a, matched, min_similarity=0.85)
    assert plan.summary()["carried"] == 0
    assert plan.skipped_low_similarity[0]["b_address"] == "0x2000"


def test_annotated_but_unmatched_function_is_reported(tmp_path):
    a = _overlay(tmp_path, "a" * 64)
    a.rename_function("0x1000", "gone_in_v2")
    plan = build_plan(a, matched=[], min_similarity=0.85)
    assert plan.skipped_unmatched == [{"a_address": "0x1000"}]


def test_unannotated_matches_do_not_appear(tmp_path):
    # A matched pair for a function A never annotated must not carry noise.
    a = _overlay(tmp_path, "a" * 64)
    matched = [{"a_address": "0x9999", "b_address": "0x8888", "similarity": 0.99}]
    plan = build_plan(a, matched, min_similarity=0.85)
    assert plan.summary() == {"carried": 0, "skipped_low_similarity": 0,
                              "skipped_unmatched": 0}


def test_address_forms_normalize_before_matching(tmp_path):
    # Overlay stores 0x1000; diff reports it uppercased — must still match.
    a = _overlay(tmp_path, "a" * 64)
    a.rename_function("0x1000", "f")
    matched = [{"a_address": "0X1000", "b_address": "0X2000", "similarity": 0.9}]
    plan = build_plan(a, matched)
    assert plan.carried and plan.carried[0].b_address == "0x2000"
