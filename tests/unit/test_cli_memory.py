"""Smoke tests for the chimera memory CLI command group."""
from click.testing import CliRunner

from chimera.cli import main


def test_memory_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "memory" in r.output


def test_memory_help_lists_subcommands():
    r = CliRunner().invoke(main, ["memory", "--help"])
    assert r.exit_code == 0
    assert "pslist" in r.output
    assert "netstat" in r.output
    assert "malfind" in r.output
    assert "findings" in r.output


def test_memory_pslist_help_works():
    r = CliRunner().invoke(main, ["memory", "pslist", "--help"])
    assert r.exit_code == 0


def test_memory_netstat_help_works():
    r = CliRunner().invoke(main, ["memory", "netstat", "--help"])
    assert r.exit_code == 0


def test_memory_findings_help_works():
    r = CliRunner().invoke(main, ["memory", "findings", "--help"])
    assert r.exit_code == 0
