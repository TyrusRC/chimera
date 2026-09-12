"""reFlutter adapter — Flutter dynamic instrumentation / traffic-MITM repackaging.

The tool is external and interactive; these tests mock subprocess to verify the
adapter feeds the right stdin (mode + proxy IP), locates release.RE.apk, and
degrades cleanly when the tool is missing or an input is invalid.
"""
import subprocess

import pytest

from chimera.adapters.reflutter_adapter import ReflutterAdapter, _find_patched_apk


@pytest.fixture
def fake_bin(tmp_path):
    """A real, executable stub so is_available() passes (subprocess is mocked)."""
    b = tmp_path / "reflutter"
    b.write_text("#!/bin/sh\n")
    b.chmod(0o755)
    return str(b)


def test_unavailable_when_binary_missing():
    a = ReflutterAdapter(binary_path=None)
    a._binary = None
    r = a.patch("app.apk", "/tmp/x", mode="traffic", proxy_ip="10.0.0.1")
    assert r.success is False and "not found" in r.stderr


def test_traffic_mode_requires_proxy(tmp_path, fake_bin):
    a = ReflutterAdapter(binary_path=fake_bin)
    r = a.patch("app.apk", tmp_path, mode="traffic", proxy_ip=None)
    assert r.success is False and "proxy" in r.stderr.lower()


def test_traffic_patch_feeds_stdin_and_finds_apk(tmp_path, fake_bin, monkeypatch):
    seen = {}

    def fake_run(argv, input=None, capture_output=None, text=None, cwd=None,
                 timeout=None, check=None):
        seen["argv"] = argv
        seen["input"] = input
        seen["cwd"] = cwd
        (tmp_path / "release.RE.apk").write_bytes(b"PK\x03\x04")

        class P:
            returncode = 0
            stdout = "engine patched"
            stderr = ""
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    a = ReflutterAdapter(binary_path=fake_bin)
    r = a.patch("app.apk", tmp_path, mode="traffic", proxy_ip="192.168.1.9")

    assert r.success is True
    assert r.patched_apk.endswith("release.RE.apk")
    assert seen["input"] == "1\n192.168.1.9\n"   # option 1 then the proxy IP
    assert seen["cwd"] == str(tmp_path)
    assert "192.168.1.9:8083" in r.hint


def test_offset_mode_stdin_is_option_two(tmp_path, fake_bin, monkeypatch):
    def fake_run(argv, input=None, **_kw):
        assert input == "2\n"                    # offset mode, no IP
        (tmp_path / "release.RE.apk").write_bytes(b"PK")

        class P:
            returncode = 0
            stdout = ""
            stderr = ""
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    a = ReflutterAdapter(binary_path=fake_bin)
    r = a.patch("app.apk", tmp_path, mode="offset")
    assert r.success is True and "dump.dart" in r.hint


def test_find_patched_apk_fallback(tmp_path):
    (tmp_path / "demo.RE.apk").write_bytes(b"x")
    assert _find_patched_apk(tmp_path).endswith("demo.RE.apk")
    assert _find_patched_apk(tmp_path / "empty") is None
