"""Graceful-degradation tests for the research-add shims.

We deliberately do not require the upstream tools (binquery, lief, a real
LLM) to be present in CI; the modules promise to no-op cleanly without
them and these tests pin that contract.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from unittest import mock

import pytest

from chimera.adapters.binquery_adapter import BinQueryAdapter
from chimera.pipelines.firmware_agent_loop import run_firmware_agent_loop
from chimera.pipelines.iokit_surface import parse_iokit_methods


# ---------- binquery -------------------------------------------------------


def test_binquery_unavailable_when_no_pkg_no_cli():
    adapter = BinQueryAdapter()
    # Force the import to fail and PATH lookup to miss.
    with mock.patch.dict(sys.modules, {"binquery": None}):
        with mock.patch.object(shutil, "which", return_value=None):
            assert adapter.is_available() is False
            result = adapter.search(Path("/tmp/whatever"), "find aes")
    assert result["ok"] is False
    assert result["matches"] == []
    assert "not installed" in result["note"]


def test_binquery_uses_inprocess_api_when_available():
    fake = mock.MagicMock()
    fake.search.return_value = [
        {"address": "0x1000", "score": 0.9, "rationale": "matches aes s-box"},
        {"addr": "0x2000", "score": "0.5"},   # alt key + str score
        {"no_address": "skipme"},
    ]
    adapter = BinQueryAdapter()
    with mock.patch.dict(sys.modules, {"binquery": fake}):
        # Bypass the cached probe so the patched module is picked up.
        adapter._tried = False
        adapter._mod = None
        result = adapter.search(Path("/tmp/x"), "aes")
    assert result["ok"] is True
    assert len(result["matches"]) == 2
    assert result["matches"][0]["address"] == "0x1000"
    assert result["matches"][1]["score"] == 0.5


def test_binquery_cli_only_returns_not_yet_wired_note():
    adapter = BinQueryAdapter()
    with mock.patch.dict(sys.modules, {"binquery": None}):
        with mock.patch.object(shutil, "which", return_value="/usr/bin/binquery"):
            assert adapter.is_available() is True
            result = adapter.search(Path("/tmp/x"), "q")
    assert result["ok"] is False
    assert "pip install binquery" in result["note"]


# ---------- firmware agent loop --------------------------------------------


def test_firmware_loop_with_no_llm_returns_structured_empty():
    targets = [
        {"address": "0x10c0", "context": "void f() {}"},
        {"address": "0x20c0", "context": "void g() {}"},
    ]
    out = run_firmware_agent_loop(targets, llm_client=None, max_rounds=3)
    assert len(out) == 2
    for entry in out:
        assert "address" in entry
        # No LLM → no sinks proposed → no rounds executed.
        assert entry["rounds"] == []


def test_firmware_loop_executes_until_proposer_dries_up():
    proposer_calls = {"n": 0}

    def proposer(_llm, _target, _prior):
        proposer_calls["n"] += 1
        # Round 1+2 produce one sink, round 3 produces nothing → early exit.
        if proposer_calls["n"] <= 2:
            return [{"description": "memcpy len-arg"}]
        return []

    def fuzzer(_target, sinks):
        return [{"sink_index": 0, "outcome": "crash"} for _ in sinks]

    out = run_firmware_agent_loop(
        [{"address": "0x1"}], llm_client=object(),
        max_rounds=5, propose_sinks=proposer, fuzz=fuzzer,
    )
    assert len(out) == 1
    rounds = out[0]["rounds"]
    assert len(rounds) == 2
    assert rounds[0]["findings"] == [{"sink_index": 0, "outcome": "crash"}]
    assert proposer_calls["n"] == 3   # 2 productive + 1 empty


def test_firmware_loop_rejects_zero_rounds():
    with pytest.raises(ValueError):
        run_firmware_agent_loop([], llm_client=None, max_rounds=0)


def test_firmware_loop_handles_llm_exception_in_default_proposer():
    class BoomLLM:
        def complete(self, _prompt):
            raise RuntimeError("rate limit")
    out = run_firmware_agent_loop(
        [{"address": "0x1", "context": "code"}],
        llm_client=BoomLLM(),
        max_rounds=2,
    )
    # Exception suppressed → no sinks → empty rounds.
    assert out == [{"address": "0x1", "rounds": []}]


# ---------- iokit surface --------------------------------------------------


def test_iokit_missing_file_returns_note(tmp_path):
    result = parse_iokit_methods(tmp_path / "does_not_exist.kext")
    assert len(result) == 1
    assert result[0]["selector"] == -1
    assert "does not exist" in result[0]["note"]


def test_iokit_no_lief_returns_install_note(tmp_path):
    fake = tmp_path / "fake.kext"
    fake.write_bytes(b"\x00" * 256)
    # Hide lief from the importer regardless of whether it's installed.
    with mock.patch.dict(sys.modules, {"lief": None}):
        result = parse_iokit_methods(fake)
    assert len(result) == 1
    assert result[0]["selector"] == -1
    assert "lief" in result[0]["note"].lower()


def test_iokit_lief_parse_error_surfaces_as_note(tmp_path):
    fake = tmp_path / "junk.kext"
    fake.write_bytes(b"junk")
    fake_lief = mock.MagicMock()
    fake_lief.parse.side_effect = RuntimeError("malformed")
    with mock.patch.dict(sys.modules, {"lief": fake_lief}):
        result = parse_iokit_methods(fake)
    assert len(result) == 1
    assert "lief parse error" in result[0]["note"]
