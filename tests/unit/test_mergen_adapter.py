"""Tests for the Mergen VMProtect / Themida devirtualizer adapter.

Mergen is a heavy opt-in subprocess tool. The contract here is the
same as the other optional adapters: `is_available()` is cheap and
idempotent, `analyze()` degrades gracefully when the binary is
missing, and the env-var / constructor overrides resolve correctly.
"""

from __future__ import annotations

import asyncio

from chimera.adapters.base import ToolCategory
from chimera.adapters.mergen_adapter import MergenAdapter


# ---------- availability ---------------------------------------------------


def test_mergen_unavailable_without_binary(monkeypatch):
    monkeypatch.delenv("CHIMERA_MERGEN_BIN", raising=False)
    # Hide any real mergen from PATH for the test.
    monkeypatch.setenv("PATH", "/tmp")
    a = MergenAdapter()
    assert a.is_available() is False
    assert a.binary_path() in (None, "")


def test_mergen_is_available_is_idempotent(monkeypatch):
    monkeypatch.delenv("CHIMERA_MERGEN_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = MergenAdapter()
    first = a.is_available()
    second = a.is_available()
    assert first == second


def test_mergen_honours_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "mergen"
    fake.write_text("#!/bin/sh\necho ok\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_MERGEN_BIN", str(fake))
    a = MergenAdapter()
    assert a.is_available() is True
    assert a.binary_path() == str(fake)


def test_mergen_constructor_override_wins(monkeypatch, tmp_path):
    """An explicit binary= kwarg must take precedence over $PATH / env."""
    monkeypatch.delenv("CHIMERA_MERGEN_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    fake = tmp_path / "mergen"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    a = MergenAdapter(binary=str(fake))
    assert a.is_available() is True
    assert a.binary_path() == str(fake)


# ---------- shape ----------------------------------------------------------


def test_mergen_name():
    assert MergenAdapter().name() == "mergen"


def test_mergen_supported_formats_covers_pe_and_elf():
    fmts = set(MergenAdapter().supported_formats())
    assert {"pe", "elf"}.issubset(fmts)


def test_mergen_resource_estimate_is_heavy(tmp_path):
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 1024)
    est = MergenAdapter().resource_estimate(str(sample))
    assert est.category == ToolCategory.HEAVY
    # Floor is 2 GB regardless of input size — VMP IR is just huge.
    assert est.memory_mb >= 2048


# ---------- graceful degradation ------------------------------------------


def test_mergen_analyze_returns_error_when_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("CHIMERA_MERGEN_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = MergenAdapter()
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    result = asyncio.run(a.analyze(str(sample), {"start": "0x401000"}))
    assert result["available"] is False
    assert result["devirt_output"] is None
    assert result["lifted_functions"] == []
    assert result["error"] and "not found" in result["error"]


def test_mergen_analyze_requires_start_address(monkeypatch, tmp_path):
    """Without options['start'], analyze must report a clear error rather
    than spawning mergen with nonsense arguments."""
    fake = tmp_path / "mergen"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_MERGEN_BIN", str(fake))
    a = MergenAdapter()
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    result = asyncio.run(a.analyze(str(sample), {}))
    assert result["available"] is True
    assert result["error"] and "start" in result["error"].lower()
