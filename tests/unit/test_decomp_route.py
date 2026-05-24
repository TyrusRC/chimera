"""Decomp route returns post-processed C for backends that have data.

We can't exercise live r2 without a binary on PATH, so we shim the
adapter to return canned output and assert the post-processor ran.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chimera.api.routes.projects import _store
from chimera.api.server import create_app
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo, ImportEntry
from chimera.model.program import UnifiedProgramModel


PID = "decomp-test"
SHA = "d" * 64
ADDR = "0x140001000"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CHIMERA_PROJECT_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "cache"))
    return TestClient(create_app())


@pytest.fixture(autouse=True)
async def seed_project(monkeypatch, tmp_path):
    """Project with cached Ghidra decomp on the function — Ghidra path exercised."""
    bi = BinaryInfo(
        path=Path("/tmp/x"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    f = FunctionInfo(
        address=ADDR, name="decode_license", original_name="FUN_140001000",
        language="c", classification="crypto", layer="native", source_backend="ghidra",
        decompiled="undefined4 FUN_00140002000(int iVar1) { return DAT_00140005000; }",
    )
    m.add_function(f)
    m.add_function(FunctionInfo(
        address="0x140002000", name="emit_log", original_name="emit_log",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_string(address="0x140005000", value="license invalid")
    m.add_import(ImportEntry(dll="kernel32.dll", name="LoadLibraryA", address="0x140006000"))
    await _store.set(PID, {
        "name": "test.exe", "path": "/tmp/x", "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 2, "string_count": 1, "status": "complete",
        "model": m,
    })

    # Stub r2 so the test doesn't need radare2 on PATH. The adapter's
    # is_available() check is what gates the live path; force True and
    # patch the decompile entrypoint to a canned response.
    from chimera.api.routes import decomp
    monkeypatch.setattr(
        decomp, "_r2_decompile_sync",
        lambda _adapter, _path, _addr: {
            "ok": True, "backend": "radare2",
            "address": ADDR,
            "code": "void FUN_00140002000(int iVar1) { puts(DAT_00140005000); }",
            "lines": 1,
        },
    )
    monkeypatch.setattr(
        "chimera.adapters.radare2.Radare2Adapter.is_available",
        lambda self: True,
    )
    yield


@pytest.mark.asyncio
async def test_decomp_ghidra_runs_postprocessor(client):
    r = client.get(f"/api/projects/{PID}/functions/{ADDR}/decomp?backend=ghidra")
    assert r.status_code == 200, r.text
    body = r.json()
    g = body["backends"]["ghidra"]
    assert g["ok"] is True
    assert "license invalid" in g["code"]      # DAT → string literal
    assert "emit_log" in g["code"]              # FUN → recovered name
    assert "FUN_00140002000" not in g["code"]
    assert "iVar1" not in g["code"] or "i1" in g["code"]  # iVar1 normalized


@pytest.mark.asyncio
async def test_decomp_r2_runs_postprocessor(client):
    r = client.get(f"/api/projects/{PID}/functions/{ADDR}/decomp?backend=r2")
    assert r.status_code == 200, r.text
    body = r.json()
    rr = body["backends"]["r2"]
    assert rr["ok"] is True
    assert "license invalid" in rr["code"]
    # The post-processor reports how much it changed.
    assert rr["inserted_strings"] >= 1
    assert rr["inserted_names"] >= 1


@pytest.mark.asyncio
async def test_decomp_all_returns_both_backends(client):
    r = client.get(f"/api/projects/{PID}/functions/{ADDR}/decomp?backend=all")
    assert r.status_code == 200, r.text
    backends = r.json()["backends"]
    assert "r2" in backends and "ghidra" in backends


@pytest.mark.asyncio
async def test_decomp_invalid_backend_400(client):
    r = client.get(f"/api/projects/{PID}/functions/{ADDR}/decomp?backend=bogus")
    assert r.status_code == 422  # FastAPI Query regex validation


@pytest.mark.asyncio
async def test_decomp_unknown_function_404(client):
    r = client.get(f"/api/projects/{PID}/functions/0xdeaddead/decomp?backend=r2")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_decomp_ghidra_without_cache_reports_friendly_error(client):
    # Drop the cached decompilation so the Ghidra branch hits its degraded path.
    proj = await _store.get(PID)
    proj["model"].get_function(ADDR).decompiled = None
    await _store.set(PID, proj)

    r = client.get(f"/api/projects/{PID}/functions/{ADDR}/decomp?backend=ghidra")
    assert r.status_code == 200
    g = r.json()["backends"]["ghidra"]
    assert g["ok"] is False
    assert "Ghidra" in g["error"]
