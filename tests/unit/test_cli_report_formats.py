"""Smoke tests for the new --format options on `chimera report`."""
from click.testing import CliRunner

from chimera.cli import main


def test_report_help_lists_masvs():
    r = CliRunner().invoke(main, ["report", "--help"])
    assert r.exit_code == 0
    assert "masvs" in r.output


def test_report_help_lists_cvss():
    r = CliRunner().invoke(main, ["report", "--help"])
    assert r.exit_code == 0
    assert "cvss" in r.output


def test_report_help_lists_sbom():
    r = CliRunner().invoke(main, ["report", "--help"])
    assert r.exit_code == 0
    assert "sbom" in r.output


def test_report_help_describes_format_choices():
    r = CliRunner().invoke(main, ["report", "--help"])
    assert r.exit_code == 0
    assert "MASVS" in r.output or "CVSS" in r.output or "SBOM" in r.output
