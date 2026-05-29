"""Tests for VarBERT, EMBER, and B(l)utter optional adapters.

All three are opt-in: they depend on packages or binaries we don't ship
by default. The test contract for each is the same — `is_available()`
must be idempotent and never raise, and the user-facing entry points
(API + CLI) must degrade with a clear, actionable error.
"""

from __future__ import annotations

import os

import pytest

from chimera.adapters.blutter_adapter import BlutterAdapter, detect_libapp
from chimera.adapters.varbert_adapter import VarBertAdapter
from chimera.detection_engineering.ember_classify import EmberClassifier


# ---------- VarBERT --------------------------------------------------------


def test_varbert_is_available_is_idempotent():
    a = VarBertAdapter()
    first = a.is_available()
    second = a.is_available()
    assert first == second


def test_varbert_rename_returns_empty_when_unavailable(monkeypatch):
    """Without varbert_api, rename_function must no-op (not raise)."""
    a = VarBertAdapter()
    if a.is_available():
        pytest.skip("varbert_api is installed; tests covers the absent path")
    assert a.rename_function("int foo(int a) { return a; }") == []


def test_varbert_supported_formats_covers_desktop_targets():
    a = VarBertAdapter()
    fmts = set(a.supported_formats())
    assert {"elf", "macho", "pe"}.issubset(fmts)


# ---------- EMBER ----------------------------------------------------------


def test_ember_is_available_is_idempotent():
    c = EmberClassifier()
    first = c.is_available()
    second = c.is_available()
    assert first == second


def test_ember_classify_returns_none_without_deps(monkeypatch, tmp_path):
    c = EmberClassifier()
    if c.is_available():
        pytest.skip("lightgbm + lief installed; covers the absent path")
    fake_pe = tmp_path / "x.exe"
    fake_pe.write_bytes(b"MZ" + b"\x00" * 64)
    assert c.classify(fake_pe) is None


def test_ember_classify_returns_none_when_model_missing(monkeypatch, tmp_path):
    c = EmberClassifier(model_path=tmp_path / "nonexistent.txt")
    if not c.is_available():
        pytest.skip("EMBER deps missing; can't test model-absent path")
    # Even with deps installed, no model means we can't classify.
    fake_pe = tmp_path / "x.exe"
    fake_pe.write_bytes(b"MZ" + b"\x00" * 64)
    assert c.classify(fake_pe) is None


# ---------- B(l)utter ------------------------------------------------------


def test_blutter_unavailable_without_binary(monkeypatch):
    monkeypatch.delenv("CHIMERA_BLUTTER_BIN", raising=False)
    # Hide blutter from PATH for the test.
    monkeypatch.setenv("PATH", "/tmp")
    a = BlutterAdapter()
    assert a.is_available() is False
    assert a.binary_path() in (None, "")


def test_blutter_honours_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "blutter"
    fake.write_text("#!/bin/sh\necho ok\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_BLUTTER_BIN", str(fake))
    a = BlutterAdapter()
    assert a.is_available() is True
    assert a.binary_path() == str(fake)


def test_blutter_extract_reports_failure_when_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("CHIMERA_BLUTTER_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = BlutterAdapter()
    result = a.extract(tmp_path / "libapp.so", tmp_path / "out")
    assert result.success is False
    assert "not found" in result.stderr


def test_blutter_extract_runs_real_subprocess(monkeypatch, tmp_path):
    # Build a tiny shell script that pretends to be blutter.
    fake = tmp_path / "blutter"
    fake.write_text(
        "#!/bin/sh\n"
        "echo \"blutter $1 -> $2\"\n"
        "mkdir -p \"$2\"\n"
        "echo 'class Hello { void foo() {} }' > \"$2/hello.dart\"\n"
        "exit 0\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_BLUTTER_BIN", str(fake))
    a = BlutterAdapter()
    out = tmp_path / "out"
    result = a.extract(tmp_path / "libapp.so", out)
    assert result.success is True
    assert result.classes_dumped == 1
    assert (out / "hello.dart").exists()


def test_detect_libapp_finds_arm64_lib(tmp_path):
    """detect_libapp should prefer arm64-v8a > arm64 > others."""
    a64 = tmp_path / "lib" / "arm64-v8a" / "libapp.so"
    a64.parent.mkdir(parents=True)
    a64.write_bytes(b"\x7fELF" + b"\x00" * 32)
    other = tmp_path / "lib" / "armeabi-v7a" / "libapp.so"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"\x7fELF" + b"\x00" * 32)
    detected = detect_libapp(tmp_path)
    assert detected == a64


def test_detect_libapp_returns_none_when_absent(tmp_path):
    (tmp_path / "lib" / "arm64-v8a").mkdir(parents=True)
    assert detect_libapp(tmp_path) is None
