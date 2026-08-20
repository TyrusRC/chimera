"""Tracer orchestration — the pure glue; the live path is SDK-gated."""
from __future__ import annotations

import json

import pytest

from chimera.dotnet.tracer import TraceResult, _parse_trace, installed_core_runtime


def test_parse_trace_reads_calls_and_hook_count(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join([
        json.dumps({"event": "hooks_installed", "count": 2}),
        json.dumps({"event": "call", "method": "cmp",
                    "args": [{"type": "byte[]", "len": 3, "hex": "414243",
                              "ascii": "ABC"}],
                    "result": {"type": "bool", "value": False}}),
        json.dumps({"event": "call", "method": "target", "args": [],
                    "result": {"type": "byte[]", "len": 3, "hex": "58595A",
                               "ascii": "XYZ"}}),
        json.dumps({"event": "done"}),
    ]))
    r = _parse_trace(trace)
    assert r.available is True
    assert r.hooks_installed == 2
    assert len(r.calls) == 2


def test_byte_values_collects_args_and_returns(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join([
        json.dumps({"event": "call", "method": "cmp",
                    "args": [{"type": "byte[]", "len": 3, "hex": "414243",
                              "ascii": "ABC"}],
                    "result": {"type": "bool", "value": False}}),
        json.dumps({"event": "call", "method": "target", "args": [],
                    "result": {"type": "byte[]", "len": 3, "hex": "58595A",
                               "ascii": "XYZ"}}),
    ]))
    vals = _parse_trace(trace).byte_values()
    assert ("cmp", "ABC", "414243") in vals
    assert ("target", "XYZ", "58595A") in vals


def test_parse_trace_tolerates_garbage_lines(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text("not json\n" + json.dumps({"event": "done"}) + "\nalso bad\n")
    r = _parse_trace(trace)
    assert r.available is True
    assert r.calls == []


def test_parse_trace_reports_missing_output(tmp_path):
    r = _parse_trace(tmp_path / "does_not_exist.jsonl")
    assert r.error is not None


def test_strings_seen_collects_string_operands(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text(json.dumps({"event": "call", "method": "v",
        "args": [{"type": "string", "value": "KEY-123"}],
        "result": {"type": "null"}}))
    assert ("v", "KEY-123") in _parse_trace(trace).strings_seen()
