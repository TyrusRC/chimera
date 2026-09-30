from click.testing import CliRunner

from chimera.cli import main


def test_vm_list_unavailable(monkeypatch):
    monkeypatch.setattr("chimera.cli.vm_cmd.get_provider", lambda name=None: None)
    r = CliRunner().invoke(main, ["vm", "list"])
    assert r.exit_code == 0
    assert "no VM provider" in r.output


def test_vm_exec_requires_snapshot_flag():
    r = CliRunner().invoke(main, ["vm", "exec", "myvm", "--", "cmd.exe"])
    assert r.exit_code != 0  # missing required --snapshot / --guest-user
