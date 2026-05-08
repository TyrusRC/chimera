"""Smoke tests for the new --no-floss / --no-ilspy / --no-pe-imports flags."""
from click.testing import CliRunner

from chimera.cli import main


def test_analyze_help_lists_no_floss():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--no-floss" in result.output


def test_analyze_help_lists_no_ilspy():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--no-ilspy" in result.output


def test_analyze_help_lists_no_pe_imports():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--no-pe-imports" in result.output


def test_analyze_help_lists_floss_timeout():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--floss-timeout" in result.output
