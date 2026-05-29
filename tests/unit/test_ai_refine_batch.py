"""Tests for the LLM-refine and batch-rename prompts + helpers."""

from __future__ import annotations

import json

import pytest

from chimera.ai import batch_rename_prompt, refine_decomp_prompt


def test_refine_prompt_forbids_inventing_semantics():
    sys_p, user_p = refine_decomp_prompt("int x = 1;", function_name="foo", address="0x100")
    assert "NEVER" in sys_p and "invent" in sys_p
    assert "foo" in user_p
    assert "0x100" in user_p
    assert "ONLY the refined C code" in user_p


def test_refine_prompt_handles_missing_metadata():
    sys_p, user_p = refine_decomp_prompt("int x = 1;")
    assert "(no metadata)" in user_p


def test_batch_rename_prompt_demands_json():
    sys_p, user_p = batch_rename_prompt(
        "int x = 1;",
        current_name="FUN_001000",
        callers=["main"],
        callees=["malloc", "free"],
    )
    assert "JSON" in user_p
    assert '"name"' in user_p and '"confidence"' in user_p
    assert "FUN_001000" in user_p
    assert "main" in user_p
    assert "malloc" in user_p
    # Sanity: the prompt should warn against hallucinations.
    assert "Hallucinations" in sys_p or "conservative" in sys_p


def test_batch_rename_prompt_tolerates_empty_neighbors():
    sys_p, user_p = batch_rename_prompt("int x = 1;")
    assert "(none)" in user_p
    assert "stripped" in user_p


def test_parse_rename_json_round_trip():
    """Lifted from cli._parse_rename_json — round-trip a model response."""
    from chimera.cli import _parse_rename_json
    raw = json.dumps({"name": "decrypt_blob", "confidence": 0.91})
    parsed = _parse_rename_json(raw)
    assert parsed == {"name": "decrypt_blob", "confidence": 0.91}


def test_parse_rename_json_strips_code_fences():
    from chimera.cli import _parse_rename_json
    raw = "```json\n{\"name\": \"decode\", \"confidence\": 0.8}\n```"
    parsed = _parse_rename_json(raw)
    assert parsed == {"name": "decode", "confidence": 0.8}


def test_parse_rename_json_extracts_brace_block_from_prose():
    """The model sometimes wraps JSON in apologetic prose. Don't reject — extract."""
    from chimera.cli import _parse_rename_json
    raw = 'Here is my best guess: {"name": "alpha", "confidence": 0.55}\n'
    parsed = _parse_rename_json(raw)
    assert parsed == {"name": "alpha", "confidence": 0.55}


def test_parse_rename_json_clamps_out_of_range_confidence():
    from chimera.cli import _parse_rename_json
    raw = json.dumps({"name": "f", "confidence": 1.7})
    parsed = _parse_rename_json(raw)
    assert parsed["confidence"] == 1.0


def test_parse_rename_json_returns_none_on_malformed():
    from chimera.cli import _parse_rename_json
    assert _parse_rename_json("not json") is None
    assert _parse_rename_json("{") is None
    assert _parse_rename_json('{"confidence": 0.5}') is None  # missing name
