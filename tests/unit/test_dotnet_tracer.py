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


def test_numeric_streams_splits_return_and_args(tmp_path):
    """A VM memory-read primitive returns one key byte per call; the loop
    constant rides in the args. The two channels must stay separate so the
    return channel reconstructs cleanly."""
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join([
        json.dumps({"event": "call", "method": "read",
                    "args": [{"type": "int", "value": 908506164}],
                    "result": {"type": "int", "value": 78}}),   # 'N'
        json.dumps({"event": "call", "method": "read",
                    "args": [{"type": "int", "value": 908506164}],
                    "result": {"type": "char", "value": "E", "code": 69}}),
    ]))
    streams = _parse_trace(trace).numeric_streams()
    assert streams["read"]["return"] == [78, 69]
    assert streams["read"]["args"] == [908506164, 908506164]


def test_reconstruct_ascii_marks_nonprintables():
    assert TraceResult.reconstruct_ascii([78, 69, 88, 0, 45]) == "NEX.-"


def test_trace_injects_pinvoke_spec(monkeypatch, tmp_path):
    """`neutralize_pinvoke=True` must prepend the harness spec, and
    `stdin_lines` must join with newlines — both without an SDK present."""
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["stdin"] = cmd[4] if len(cmd) > 4 else None

        class P:
            returncode = 0
            stdout = ""
            stderr = ""
        (tmp_path / "trace.jsonl").write_text(
            json.dumps({"event": "done"}))
        return P()

    import chimera.dotnet.tracer as tr
    monkeypatch.setattr(tr, "installed_core_runtime", lambda: "6.0.8")
    monkeypatch.setattr(tr, "build_harness", lambda wd: tmp_path / "h.dll")
    monkeypatch.setattr(tr, "build_win32_stub", lambda wd: tmp_path / "stub.so")
    monkeypatch.setattr(tr.shutil, "copy", lambda *a, **k: None)
    monkeypatch.setattr(tr.subprocess, "run", fake_run)

    tr.trace(tmp_path / "x.exe", ["Layoutgrj"],
             stdin_lines=["7", "KEY", "8"], neutralize_pinvoke=True,
             work_dir=tmp_path, timeout=10)
    assert "@neutralize-pinvoke" in captured["cmd"]
    assert captured["stdin"] == "7\nKEY\n8"
