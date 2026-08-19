"""chimera doctor — exit code and output-shape smoke tests."""
from __future__ import annotations

from click.testing import CliRunner

from chimera.cli import main


def test_doctor_runs_and_lists_core_decompilers():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "Core decompilers:" in result.output
    assert "radare2" in result.output
    assert "ghidra" in result.output


def test_doctor_fails_when_no_core_decompiler_available(monkeypatch):
    from chimera.adapters.ghidra import GhidraAdapter
    from chimera.adapters.radare2 import Radare2Adapter

    monkeypatch.setattr(Radare2Adapter, "is_available", lambda self: False)
    monkeypatch.setattr(GhidraAdapter, "is_available", lambda self: False)

    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 1
    assert "neither radare2 nor Ghidra is available" in result.output


def test_doctor_redacts_db_url(monkeypatch):
    monkeypatch.setenv("CHIMERA_DB_URL", "postgresql://user:hunter2@host/db")
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert "hunter2" not in result.output
    assert "redacted" in result.output
