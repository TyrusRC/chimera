"""Unit tests for HermesDecAdapter CLI flag composition."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


pytestmark = pytest.mark.asyncio


async def test_hermes_dec_argv_shape(tmp_path: Path, monkeypatch):
    from chimera.adapters.hermes_dec import HermesDecAdapter

    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 60)
    out_dir = tmp_path / "decompiled"

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            (out_dir / "decompiled.js").write_text("// decompiled")
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        out_dir.mkdir(parents=True, exist_ok=True)
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = HermesDecAdapter()
    result = await adapter.analyze(str(bundle), {"output_dir": str(out_dir)})

    argv = captured[0]
    assert argv[0] == "hermes-dec"
    assert str(bundle) in argv
    assert "-o" in argv
    assert any(arg.endswith("decompiled.js") for arg in argv)
    assert result["decompiled"] is True
    assert result["return_code"] == 0
    assert Path(result["output_file"]).exists()


async def test_hermes_dec_failure_parses_bytecode_version(tmp_path: Path, monkeypatch):
    from chimera.adapters.hermes_dec import HermesDecAdapter

    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 60)
    out_dir = tmp_path / "decompiled"

    class FakeProc:
        returncode = 1
        async def communicate(self):
            return b"", b"Unsupported bytecode version: 96"

    async def fake_exec(*argv, **kw):
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = HermesDecAdapter()
    result = await adapter.analyze(str(bundle), {"output_dir": str(out_dir)})

    assert result["decompiled"] is False
    assert result["hermes_bytecode_version"] == 96
    assert "Unsupported" in result["error"]


async def test_hermes_dec_default_output_dir(tmp_path: Path, monkeypatch):
    from chimera.adapters.hermes_dec import HermesDecAdapter

    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 60)

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = HermesDecAdapter()
    await adapter.analyze(str(bundle), {})

    argv = captured[0]
    assert any("hermes_dec" in arg for arg in argv) or any(arg.endswith("decompiled.js") for arg in argv)


def test_hermes_dec_adapter_metadata():
    from chimera.adapters.hermes_dec import HermesDecAdapter

    a = HermesDecAdapter()
    assert a.name() == "hermes_dec"
    assert "hbc" in a.supported_formats()
    assert "bundle" in a.supported_formats()
