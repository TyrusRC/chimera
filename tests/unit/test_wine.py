"""Wine dynamic-oracle primitive — tested without invoking wine.

CI has no wine and must never run an arbitrary exe, so these tests exercise the
pure helpers and monkeypatch shutil.which / subprocess so the launch path is
observed (argv is a LIST, never a shell string) but nothing executes.
"""
from __future__ import annotations

import subprocess

import pytest

from chimera.dynamic import wine


def test_needle_variants_narrow_and_wide():
    assert wine._needle_variants("AB") == [b"AB", b"A\x00B\x00"]


def test_needle_variants_bytes_passthrough():
    assert wine._needle_variants(b"\xde\xad") == [b"\xde\xad"]


def test_wine_env_quiets_and_isolates(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    env = wine._wine_env("/scratch/wp", headless=True, extra={"FOO": "bar"})
    assert env["WINEPREFIX"] == "/scratch/wp"
    assert env["WINEDEBUG"] == "-all"
    assert env["WINEDLLOVERRIDES"] == wine._DLL_OVERRIDES
    assert "DISPLAY" not in env            # dropped for headless
    assert env["FOO"] == "bar"


def test_wine_env_keeps_display_when_not_headless(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":99")
    env = wine._wine_env("/scratch/wp", headless=False)
    assert env["DISPLAY"] == ":99"


def test_run_reports_missing_wine(monkeypatch):
    monkeypatch.setattr(wine.shutil, "which", lambda _n: None)
    res = wine.run_under_wine("/bin/true")
    assert res["ran"] is False
    assert "wine not found" in res["error"]


def test_run_reports_missing_exe(monkeypatch):
    monkeypatch.setattr(wine.shutil, "which", lambda n: "/usr/bin/wine")
    res = wine.run_under_wine("/no/such/file.exe")
    assert res["ran"] is False
    assert "exe not found" in res["error"]


def test_run_builds_argv_list_never_shell(monkeypatch, tmp_path):
    exe = tmp_path / "t.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(wine.shutil, "which",
                        lambda n: "/usr/bin/wine" if n == "wine" else None)

    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["kw"] = kw
        assert isinstance(argv, list)          # never a shell string
        assert kw.get("shell") in (None, False)
        return subprocess.CompletedProcess(argv, 0, b"out", b"err")

    monkeypatch.setattr(wine.subprocess, "run", fake_run)
    res = wine.run_under_wine(str(exe), ["-r", "42"])
    assert captured["argv"] == ["/usr/bin/wine", str(exe), "-r", "42"]
    assert res["ran"] and res["returncode"] == 0
    assert res["stdout"] == "out" and res["stderr"] == "err"


def test_run_timeout_reported(monkeypatch, tmp_path):
    exe = tmp_path / "t.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(wine.shutil, "which",
                        lambda n: "/usr/bin/wine" if n == "wine" else None)

    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"),
                                        output=b"partial", stderr=b"")

    monkeypatch.setattr(wine.subprocess, "run", fake_run)
    res = wine.run_under_wine(str(exe), timeout=1)
    assert res["timed_out"] is True and res["ran"] is True
    assert res["stdout"] == "partial"


def test_run_xvfb_requested_but_absent(monkeypatch, tmp_path):
    exe = tmp_path / "t.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(wine.shutil, "which",
                        lambda n: "/usr/bin/wine" if n == "wine" else None)
    res = wine.run_under_wine(str(exe), xvfb=True)
    assert res["ran"] is False and "xvfb-run not found" in res["error"]
