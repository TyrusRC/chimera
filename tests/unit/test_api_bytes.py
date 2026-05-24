"""GET /api/projects/{id}/bytes?offset=N&length=M returns a slice of the binary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from chimera.api.routes.projects import _store
from chimera.api.server import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.mark.asyncio
async def test_get_bytes_returns_hex_slice(tmp_path, client, monkeypatch):
    # Sandbox guard requires the binary to live under an allow-listed root.
    monkeypatch.setenv("CHIMERA_DATA_DIR", str(tmp_path))
    p = tmp_path / "sample.bin"
    p.write_bytes(bytes(range(256)))
    await _store.set("test-bytes", {
        "name": "sample.bin", "path": str(p), "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    r = client.get("/api/projects/test-bytes/bytes?offset=0&length=16")
    assert r.status_code == 200
    body = r.json()
    assert body["offset"] == 0
    assert body["length"] == 16
    assert body["hex"] == "000102030405060708090a0b0c0d0e0f"
    assert body["total_size"] == 256


@pytest.mark.asyncio
async def test_get_bytes_clamps_to_file_size(tmp_path, client, monkeypatch):
    monkeypatch.setenv("CHIMERA_DATA_DIR", str(tmp_path))
    p = tmp_path / "s.bin"
    p.write_bytes(b"\xab\xcd")
    await _store.set("clamp", {
        "name": "s.bin", "path": str(p), "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    r = client.get("/api/projects/clamp/bytes?offset=0&length=1024")
    assert r.status_code == 200
    assert r.json()["hex"] == "abcd"


@pytest.mark.asyncio
async def test_get_bytes_404_unknown_project(client):
    r = client.get("/api/projects/no-such/bytes?offset=0&length=16")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_bytes_rejects_path_outside_allowed_roots(tmp_path, client, monkeypatch):
    """A project record pointing outside the allow-list should not be readable."""
    monkeypatch.setenv("CHIMERA_DATA_DIR", str(tmp_path))
    # Also pin the upload dir so the test doesn't accidentally inherit a real
    # ~/.chimera/uploads that happens to be a parent of `outside`.
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(tmp_path / "uploads"))
    # Write the binary to a *different* directory that is NOT in the allow-list.
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    p = outside / "secret.bin"
    p.write_bytes(b"\x00" * 16)
    await _store.set("escape", {
        "name": "secret.bin", "path": str(p), "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    r = client.get("/api/projects/escape/bytes?offset=0&length=8")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_bytes_accepts_default_upload_staging_dir(tmp_path, client, monkeypatch):
    """Files written by POST /api/projects/upload must be readable through /bytes.

    The upload route lands files under CHIMERA_UPLOAD_DIR (or ~/.chimera/uploads
    by default). The sandbox should include that root so projects created via
    the web UI's upload flow aren't 403'd on the hex view.
    """
    # Point both the data and upload dirs OUTSIDE tmp_path so we know the
    # allow-list isn't being satisfied by accident.
    monkeypatch.setenv("CHIMERA_DATA_DIR", str(tmp_path / "data"))
    upload_dir = tmp_path / "staging" / "uploads"
    upload_dir.mkdir(parents=True)
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(upload_dir))
    p = upload_dir / "abc123-sample.bin"
    p.write_bytes(b"\xde\xad\xbe\xef")
    await _store.set("upload-ok", {
        "name": "sample.bin", "path": str(p), "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    r = client.get("/api/projects/upload-ok/bytes?offset=0&length=4")
    assert r.status_code == 200, r.text
    assert r.json()["hex"] == "deadbeef"
