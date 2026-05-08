"""Smoke tests for the chimera ioc CLI command."""
from click.testing import CliRunner

from chimera.cli import main


def test_ioc_help_works():
    r = CliRunner().invoke(main, ["ioc", "--help"])
    assert r.exit_code == 0
    assert "IoC" in r.output or "ioc" in r.output.lower()


def test_ioc_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "ioc" in r.output


def test_ioc_help_lists_format_choices():
    r = CliRunner().invoke(main, ["ioc", "--help"])
    assert "table" in r.output
    assert "json" in r.output
    assert "stix" in r.output
