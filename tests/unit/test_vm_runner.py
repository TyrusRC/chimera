from chimera.dynamic.vm import runner


def test_resolve_cli_prefers_plain_then_exe(monkeypatch):
    monkeypatch.setattr("shutil.which",
                        lambda n: "/usr/bin/VBoxManage" if n == "VBoxManage" else None)
    assert runner.resolve_cli("VBoxManage") == "/usr/bin/VBoxManage"


def test_resolve_cli_falls_back_to_exe(monkeypatch):
    monkeypatch.setattr("shutil.which",
                        lambda n: "/mnt/c/x/VBoxManage.exe" if n == "VBoxManage.exe" else None)
    assert runner.resolve_cli("VBoxManage").endswith(".exe")


def test_resolve_cli_missing_returns_none(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: None)
    assert runner.resolve_cli("VBoxManage", windows_default=None) is None


def test_run_captures_and_times_out():
    ok = runner.run(["printf", "hi"], timeout=10)
    assert ok.returncode == 0 and ok.stdout == "hi" and ok.timed_out is False
    slow = runner.run(["sleep", "5"], timeout=1)
    assert slow.timed_out is True


def test_run_missing_binary_does_not_raise():
    r = runner.run(["definitely_not_a_binary_xyz"], timeout=5)
    assert r.returncode == 127 and r.timed_out is False


def test_to_windows_path_noop_off_wsl(monkeypatch):
    monkeypatch.setattr(runner, "is_wsl", lambda: False)
    assert runner.to_windows_path("/home/x") == "/home/x"
