"""Smoke tests for the chimera yara CLI command."""
from click.testing import CliRunner

from chimera.cli import main


def test_yara_help_works():
    r = CliRunner().invoke(main, ["yara", "--help"])
    assert r.exit_code == 0
    assert "YARA rule" in r.output or "yara" in r.output.lower()


def test_yara_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "yara" in r.output


def test_yara_help_lists_main_options():
    r = CliRunner().invoke(main, ["yara", "--help"])
    assert "--family" in r.output
    assert "--out" in r.output
    assert "--name" in r.output
