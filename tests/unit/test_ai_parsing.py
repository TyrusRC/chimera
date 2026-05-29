"""Tests for the shared chimera.ai.parsing helpers.

These power both `chimera ai ...` and `/api/projects/{id}/ai/...` after
the dedupe — drift here would silently desync the two surfaces.
"""

from __future__ import annotations

import json

import pytest

from chimera.ai import parse_rename_json, strip_fence
from chimera.ai.parsing import strip_fence as parsing_strip_fence
from chimera.ai.parsing import parse_rename_json as parsing_parse


def test_strip_fence_no_op_when_no_fence():
    assert strip_fence("hello world") == "hello world"
    assert strip_fence("  hello\n") == "hello"


def test_strip_fence_drops_opening_lang_and_closing_fence():
    src = "```c\nint main() { return 0; }\n```"
    assert strip_fence(src) == "int main() { return 0; }"


def test_strip_fence_drops_unlabelled_fence():
    src = "```\nbody\n```"
    assert strip_fence(src) == "body"


def test_strip_fence_keeps_text_when_only_opening_fence():
    """Half-closed fence shouldn't lose the closing delimiter if it's missing."""
    src = "```\nhello"
    # No trailing fence; we still strip the opener but leave the rest.
    assert strip_fence(src) == "hello"


def test_parse_rename_json_clean_input():
    raw = json.dumps({"name": "decrypt_blob", "confidence": 0.91})
    assert parse_rename_json(raw) == {"name": "decrypt_blob", "confidence": 0.91}


def test_parse_rename_json_strips_code_fences():
    raw = "```json\n{\"name\": \"foo\", \"confidence\": 0.5}\n```"
    assert parse_rename_json(raw) == {"name": "foo", "confidence": 0.5}


def test_parse_rename_json_extracts_from_prose():
    raw = 'Sure! {"name": "bar", "confidence": 0.4} hope that helps'
    assert parse_rename_json(raw) == {"name": "bar", "confidence": 0.4}


def test_parse_rename_json_clamps_oob_confidence():
    assert parse_rename_json('{"name": "f", "confidence": 1.7}')["confidence"] == 1.0
    assert parse_rename_json('{"name": "f", "confidence": -0.5}')["confidence"] == 0.0


def test_parse_rename_json_tolerates_string_confidence():
    """Some models emit 'confidence': '0.6' as a string. Coerce, don't reject."""
    assert parse_rename_json('{"name": "f", "confidence": "0.6"}')["confidence"] == 0.6


def test_parse_rename_json_returns_none_on_garbage():
    assert parse_rename_json("not json") is None
    assert parse_rename_json("") is None
    assert parse_rename_json("{") is None
    # Missing name → reject (we don't want overlay key None).
    assert parse_rename_json('{"confidence": 0.5}') is None


def test_canonical_parsers_are_the_module_implementations():
    """Make sure top-level re-exports really alias the parsing module."""
    assert strip_fence is parsing_strip_fence
    assert parse_rename_json is parsing_parse


def test_cli_compat_shim_delegates_to_canonical_parser():
    """The cli._parse_rename_json shim must call the canonical impl."""
    from chimera.cli import _parse_rename_json
    raw = json.dumps({"name": "shim_test", "confidence": 0.8})
    direct = parse_rename_json(raw)
    shim = _parse_rename_json(raw)
    assert direct == shim
