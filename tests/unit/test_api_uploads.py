"""POST /api/projects/upload accepts a binary file, stores it, returns the path."""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chimera.api.server import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def test_upload_returns_path(tmp_path, monkeypatch, client):
    # Force the staging dir into tmp_path
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(tmp_path))
    payload = b"PK\x05\x06" + b"\x00" * 64  # minimal zip end-of-central-dir
    files = {"file": ("sample.apk", io.BytesIO(payload), "application/octet-stream")}
    r = client.post("/api/projects/upload", files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "path" in body
    p = Path(body["path"])
    assert p.exists()
    assert p.read_bytes() == payload
    # Filename should be preserved (or a safe variant)
    assert p.name.endswith(".apk")


def test_upload_rejects_path_traversal(tmp_path, monkeypatch, client):
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(tmp_path))
    payload = b"\x00" * 32
    files = {"file": ("../../etc/passwd", io.BytesIO(payload), "application/octet-stream")}
    r = client.post("/api/projects/upload", files=files)
    # Either reject (4xx) or sanitize the filename — but the written file must be inside tmp_path
    if r.status_code == 200:
        body = r.json()
        written = Path(body["path"])
        assert tmp_path in written.resolve().parents
