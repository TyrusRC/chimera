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
async def test_get_bytes_returns_hex_slice(tmp_path, client):
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
async def test_get_bytes_clamps_to_file_size(tmp_path, client):
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
