"""Smoke tests for the chimera frida CLI subcommand group."""
from click.testing import CliRunner

from chimera.cli import main


def test_frida_subcommand_registered():
    r = CliRunner().invoke(main, ["--help"])
    assert "frida" in r.output


def test_frida_help_lists_subcommands():
    r = CliRunner().invoke(main, ["frida", "--help"])
    assert r.exit_code == 0
    assert "list" in r.output
    assert "run" in r.output
    assert "show" in r.output


def test_frida_list_runs_and_shows_bundled_scripts():
    r = CliRunner().invoke(main, ["frida", "list"])
    assert r.exit_code == 0
    # At least one of the canonical bundled scripts should appear
    assert "android-ssl-pinning-bypass" in r.output


def test_frida_list_filters_by_platform():
    r = CliRunner().invoke(main, ["frida", "list", "--platform", "ios"])
    assert r.exit_code == 0
    assert "ios" in r.output.lower()
    # No android-only scripts should leak through
    assert "android-keystore-dump" not in r.output


def test_frida_show_prints_script_source():
    r = CliRunner().invoke(main, ["frida", "show", "android-ssl-pinning-bypass"])
    assert r.exit_code == 0
    assert "Java.perform" in r.output


def test_frida_show_unknown_script_errors():
    r = CliRunner().invoke(main, ["frida", "show", "definitely-not-a-script"])
    assert r.exit_code != 0


def test_frida_run_help_works():
    r = CliRunner().invoke(main, ["frida", "run", "--help"])
    assert r.exit_code == 0
    assert "--target" in r.output
    assert "--device" in r.output
