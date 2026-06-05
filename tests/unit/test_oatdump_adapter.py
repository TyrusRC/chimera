"""Tests for the oatdump2binexport adapter and android-native-similarity
pipeline.

The community `oatdump2binexport` binary is opt-in: chimera does not
bundle it. The test contract mirrors `test_optional_adapters.py` —
`is_available()` must be idempotent, the adapter must degrade with a
clear error when the binary is absent, and the pipeline must name the
missing tool when an external dependency is not on PATH.
"""

from __future__ import annotations

import asyncio

import pytest

from chimera.adapters.oatdump_adapter import OatDumpAdapter, _parse_function_count
from chimera.pipelines.android_native_similarity import diff_apks


# ---------- adapter --------------------------------------------------------


def test_oatdump_is_available_is_idempotent(monkeypatch):
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = OatDumpAdapter()
    first = a.is_available()
    second = a.is_available()
    assert first == second


def test_oatdump_unavailable_without_binary(monkeypatch):
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = OatDumpAdapter()
    assert a.is_available() is False
    assert a.binary_path() in (None, "")
    assert a.name() == "oatdump2binexport"
    assert "oat" in a.supported_formats()
    assert "apk" in a.supported_formats()


def test_oatdump_honours_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "oatdump2binexport"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_OATDUMP2BINEXPORT_BIN", str(fake))
    a = OatDumpAdapter()
    assert a.is_available() is True
    assert a.binary_path() == str(fake)


def test_oatdump_analyze_reports_unavailable_cleanly(monkeypatch, tmp_path):
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    monkeypatch.setenv("PATH", "/tmp")
    a = OatDumpAdapter()
    result = asyncio.run(a.analyze(str(tmp_path / "classes.oat"), {}))
    assert result["available"] is False
    assert result["binexport_path"] is None
    assert result["function_count"] == 0
    assert "not found" in (result["error"] or "")


def test_oatdump_analyze_missing_input_returns_error(monkeypatch, tmp_path):
    fake = tmp_path / "oatdump2binexport"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_OATDUMP2BINEXPORT_BIN", str(fake))
    a = OatDumpAdapter()
    result = asyncio.run(a.analyze(str(tmp_path / "missing.oat"), {}))
    assert result["available"] is True
    assert result["binexport_path"] is None
    assert "does not exist" in (result["error"] or "")


def test_oatdump_analyze_runs_fake_subprocess(monkeypatch, tmp_path):
    # Pretend-to-be-oatdump2binexport: prints a "<N> functions" line and
    # writes the requested output. Lets us exercise the success branch
    # without the real tool.
    fake = tmp_path / "oatdump2binexport"
    fake.write_text(
        "#!/bin/sh\n"
        "out=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--out\" ]; then shift; out=\"$1\"; fi\n"
        "  shift\n"
        "done\n"
        "echo '42 functions exported'\n"
        "echo 'OK' > \"$out\"\n"
        "exit 0\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_OATDUMP2BINEXPORT_BIN", str(fake))
    oat = tmp_path / "classes.oat"
    oat.write_bytes(b"oat\x00" + b"\x00" * 64)
    be = tmp_path / "classes.BinExport"
    a = OatDumpAdapter()
    result = asyncio.run(a.analyze(str(oat), {"out": str(be)}))
    assert result["available"] is True
    assert result["binexport_path"] == str(be)
    assert result["function_count"] == 42
    assert result["error"] is None
    assert be.exists()


def test_oatdump_resource_estimate_light(tmp_path):
    f = tmp_path / "x.oat"
    f.write_bytes(b"\x00" * (4 * 1024 * 1024))
    est = OatDumpAdapter().resource_estimate(str(f))
    # ~3× input size in MB, LIGHT category.
    assert est.memory_mb >= 256
    assert est.category.value == "light"


def test_parse_function_count_variants():
    assert _parse_function_count("exported 17 functions\n") == 17
    assert _parse_function_count("Functions: 9\n") == 9
    assert _parse_function_count("no number here") == 0


# ---------- pipeline graceful degradation ----------------------------------


def test_pipeline_reports_missing_dex2oat(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "/tmp")
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    apk_a = tmp_path / "a.apk"
    apk_b = tmp_path / "b.apk"
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")
    result = asyncio.run(diff_apks(apk_a, apk_b, out_dir=tmp_path / "out"))
    assert result["available"] is False
    assert "dex2oat" in result["error"]


def test_pipeline_reports_missing_oatdump_when_dex2oat_present(monkeypatch, tmp_path):
    # Stage a fake dex2oat so the pipeline gets past the first check, then
    # confirm the missing-oatdump2binexport error names the tool.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_dex2oat = bin_dir / "dex2oat"
    fake_dex2oat.write_text("#!/bin/sh\nexit 0\n")
    fake_dex2oat.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    apk_a = tmp_path / "a.apk"
    apk_b = tmp_path / "b.apk"
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")
    result = asyncio.run(diff_apks(apk_a, apk_b, out_dir=tmp_path / "out"))
    assert result["available"] is False
    assert "oatdump2binexport" in result["error"]


def test_pipeline_reports_missing_bindiff(monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("dex2oat",):
        f = bin_dir / name
        f.write_text("#!/bin/sh\nexit 0\n")
        f.chmod(0o755)
    fake_oatdump = bin_dir / "oatdump2binexport"
    fake_oatdump.write_text("#!/bin/sh\nexit 0\n")
    fake_oatdump.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("CHIMERA_OATDUMP2BINEXPORT_BIN", str(fake_oatdump))
    apk_a = tmp_path / "a.apk"
    apk_b = tmp_path / "b.apk"
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")
    result = asyncio.run(diff_apks(apk_a, apk_b, out_dir=tmp_path / "out"))
    assert result["available"] is False
    assert "bindiff" in result["error"]


def test_pipeline_handles_apk_without_classes_dex(monkeypatch, tmp_path):
    # All three tools "present" — but the APKs have no classes.dex, so
    # we should get a structured (available=True, error=...) response,
    # not a crash.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("dex2oat", "bindiff"):
        f = bin_dir / name
        f.write_text("#!/bin/sh\nexit 0\n")
        f.chmod(0o755)
    fake_oatdump = bin_dir / "oatdump2binexport"
    fake_oatdump.write_text("#!/bin/sh\nexit 0\n")
    fake_oatdump.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("CHIMERA_OATDUMP2BINEXPORT_BIN", str(fake_oatdump))

    import zipfile
    apk_a = tmp_path / "a.apk"
    apk_b = tmp_path / "b.apk"
    for p in (apk_a, apk_b):
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
    result = asyncio.run(diff_apks(apk_a, apk_b, out_dir=tmp_path / "out"))
    assert result["available"] is True
    assert "classes.dex" in (result.get("error") or "")


def test_cli_registers_android_similarity_command():
    # Make sure the CLI wiring landed — chimera.cli imports
    # android_sim_cmd as a side-effect, which registers the @main.command.
    from chimera.cli import main as cli_main
    names = {c.name for c in cli_main.commands.values()}
    assert "android-similarity" in names


@pytest.mark.parametrize("isa", ["arm64", "arm", "x86_64"])
def test_pipeline_accepts_isa_parameter(monkeypatch, tmp_path, isa):
    monkeypatch.setenv("PATH", "/tmp")
    monkeypatch.delenv("CHIMERA_OATDUMP2BINEXPORT_BIN", raising=False)
    apk_a = tmp_path / "a.apk"
    apk_b = tmp_path / "b.apk"
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")
    # We're only verifying signature-acceptance; dex2oat is missing, so
    # the call should still degrade rather than reject the isa kwarg.
    result = asyncio.run(diff_apks(
        apk_a, apk_b, out_dir=tmp_path / "out", isa=isa,
    ))
    assert result["available"] is False
