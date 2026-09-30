from chimera.dynamic.vm import virtualbox
from chimera.dynamic.vm.runner import RunResult


def _prov(monkeypatch, calls, result=RunResult(0, "", "", False)):
    monkeypatch.setattr(virtualbox, "run",
                        lambda argv, **kw: calls.append((argv, kw)) or result)
    return virtualbox.VirtualBoxProvider(cli="/usr/bin/VBoxManage")


def test_list_parses_vms(monkeypatch):
    out = '"Win10 Detonate" {1234}\n"linux-lab" {5678}\n'
    p = _prov(monkeypatch, [], RunResult(0, out, "", False))
    names = [v.name for v in p.list()]
    assert names == ["Win10 Detonate", "linux-lab"]


def test_snapshot_and_revert_argv(monkeypatch):
    calls = []
    p = _prov(monkeypatch, calls)
    p.snapshot("Win10 Detonate", "clean")
    p.revert("Win10 Detonate", "clean")
    assert calls[0][0] == ["/usr/bin/VBoxManage", "snapshot", "Win10 Detonate", "take", "clean"]
    assert calls[-1][0] == ["/usr/bin/VBoxManage", "snapshot", "Win10 Detonate", "restore", "clean"]


def test_vm_name_with_spaces_is_one_argv_element(monkeypatch):
    calls = []
    _prov(monkeypatch, calls).start("Win10 Detonate")
    assert "Win10 Detonate" in calls[0][0]


def test_exec_passes_password_via_stdin_not_argv(monkeypatch):
    calls = []
    p = _prov(monkeypatch, calls, RunResult(0, "done", "", False))
    r = p.exec("vm", ["C:/x.exe", "--go"], user="u", password="s3cret", timeout=30)
    argv, kw = calls[0]
    assert "s3cret" not in " ".join(argv)
    assert kw.get("stdin") == "s3cret"
    assert r.exit_code == 0 and r.stdout == "done"


def test_copy_in_translates_host_path(monkeypatch):
    calls = []
    monkeypatch.setattr(virtualbox, "to_windows_path", lambda p: "C:\\wsl\\x.exe")
    p = _prov(monkeypatch, calls)
    p.copy_in("vm", "/home/x.exe", "C:/x.exe", user="u", password="p")
    assert "C:\\wsl\\x.exe" in calls[0][0]


def test_unavailable_when_no_cli():
    assert virtualbox.VirtualBoxProvider(cli=None).available() is False
