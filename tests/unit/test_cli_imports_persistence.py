"""Smoke tests for the chimera imports / persistence commands."""
from click.testing import CliRunner

from chimera.cli import main


def test_imports_help_works():
    r = CliRunner().invoke(main, ["imports", "--help"])
    assert r.exit_code == 0
    assert "PE imports" in r.output or "import" in r.output.lower()


def test_imports_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "imports" in r.output


def test_persistence_help_works():
    r = CliRunner().invoke(main, ["persistence", "--help"])
    assert r.exit_code == 0
    assert "persistence" in r.output.lower()


def test_persistence_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "persistence" in r.output
