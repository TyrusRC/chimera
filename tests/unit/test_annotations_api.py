"""End-to-end smoke for the annotations API."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chimera.api.routes.projects import _store
from chimera.api.server import create_app
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel


PID = "ann-test"
SHA = "b" * 64


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Pin both project_dir and cache_dir under tmp_path so overlay writes
    # don't leak into the developer's checkout.
    monkeypatch.setenv("CHIMERA_PROJECT_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "cache"))
    return TestClient(create_app())


@pytest.fixture(autouse=True)
async def seed_project():
    bi = BinaryInfo(
        path=Path("/tmp/fake"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="0x140001000", name="FUN_140001000", original_name="FUN_140001000",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    await _store.set(PID, {
        "name": "test.exe", "path": "/tmp/fake", "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 1, "string_count": 0, "status": "complete",
        "model": m,
    })
    yield


@pytest.mark.asyncio
async def test_rename_function_persists_and_updates_live_model(client):
    r = client.post(f"/api/projects/{PID}/annotations/rename", json={
        "kind": "function", "address": "0x140001000", "new_name": "decode_license",
    })
    assert r.status_code == 200, r.text

    # Live model has the new name.
    fr = client.get(f"/api/projects/{PID}/functions/0x140001000")
    assert fr.status_code == 200
    assert fr.json()["name"] == "decode_license"
    assert fr.json()["original_name"] == "FUN_140001000"

    # Listing the overlay returns the persisted state.
    lr = client.get(f"/api/projects/{PID}/annotations")
    assert lr.status_code == 200
    assert lr.json()["function_names"]["0x140001000"] == "decode_license"


@pytest.mark.asyncio
async def test_rename_variable_requires_original(client):
    r = client.post(f"/api/projects/{PID}/annotations/rename", json={
        "kind": "variable", "address": "0x140001000", "new_name": "license_byte",
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_rename_variable_persists(client):
    r = client.post(f"/api/projects/{PID}/annotations/rename", json={
        "kind": "variable", "address": "0x140001000",
        "original": "iVar1", "new_name": "license_byte",
    })
    assert r.status_code == 200
    lr = client.get(f"/api/projects/{PID}/annotations")
    assert lr.json()["variable_renames"]["0x140001000"] == {"iVar1": "license_byte"}


@pytest.mark.asyncio
async def test_add_comment_and_surface_in_function_payload(client):
    r = client.post(f"/api/projects/{PID}/annotations/comment", json={
        "address": "0x140001000", "line": 3, "text": "license check starts here",
    })
    assert r.status_code == 200

    fr = client.get(f"/api/projects/{PID}/functions/0x140001000")
    assert fr.json()["annotations"]["comments"]["3"] == "license check starts here"


@pytest.mark.asyncio
async def test_set_type_persists_and_propagates(client):
    r = client.post(f"/api/projects/{PID}/annotations/type", json={
        "address": "0x140001000", "signature": "int decode(char* in, int len)",
    })
    assert r.status_code == 200
    fr = client.get(f"/api/projects/{PID}/functions/0x140001000")
    assert fr.json()["signature"] == "int decode(char* in, int len)"


@pytest.mark.asyncio
async def test_delete_rename_restores_original_name(client):
    client.post(f"/api/projects/{PID}/annotations/rename", json={
        "kind": "function", "address": "0x140001000", "new_name": "tmp",
    })
    r = client.delete(f"/api/projects/{PID}/annotations/rename/0x140001000")
    assert r.status_code == 200 and r.json()["ok"] is True
    fr = client.get(f"/api/projects/{PID}/functions/0x140001000")
    # Back to the backend-emitted name.
    assert fr.json()["name"] == "FUN_140001000"


@pytest.mark.asyncio
async def test_404_when_project_not_analyzed(client):
    r = client.post("/api/projects/no-such/annotations/rename", json={
        "kind": "function", "address": "0x0", "new_name": "x",
    })
    assert r.status_code == 404
