"""POST /api/diff returns added / resolved findings and manifest deltas."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chimera.api.routes.projects import _store
from chimera.api.server import create_app
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig


@pytest.fixture
def client():
    return TestClient(create_app())


def _seed_cached_project(cache_dir: Path, name: str = "x.apk") -> str:
    """Materialise enough cache state that load_project resolves and snapshot loads."""
    sha = hashlib.sha256(name.encode()).hexdigest()
    cache = AnalysisCache(cache_dir)
    # An empty triage blob is enough to satisfy `cache.has(sha)`.
    cache.put_json(sha, "triage", {"format": "apk", "platform": "android"})
    return sha


@pytest.mark.asyncio
async def test_diff_unknown_project_returns_404(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()
    r = client.post(
        "/api/diff",
        json={"a": "deadbeefcafefeed", "b": "deadbeefcafefee0"},
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_diff_two_cached_projects_returns_shape(tmp_path, client, monkeypatch):
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "cache"))
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    sha_a = _seed_cached_project(cache_dir, "a.apk")
    sha_b = _seed_cached_project(cache_dir, "b.apk")

    # Pin the projects in the store so the route's existence check passes.
    await _store.set(sha_a[:16], {
        "name": "a.apk", "path": "/a.apk", "platform": "android",
        "format": "apk", "framework": "java",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    await _store.set(sha_b[:16], {
        "name": "b.apk", "path": "/b.apk", "platform": "android",
        "format": "apk", "framework": "java",
        "function_count": 0, "string_count": 0, "status": "complete",
    })

    r = client.post("/api/diff", json={"a": sha_a, "b": sha_b})
    assert r.status_code == 200, r.text
    body = r.json()
    # Shape check — exact contents depend on cached state.
    for key in (
        "a_sha256", "b_sha256",
        "permissions_added", "permissions_removed",
        "exported_added", "exported_removed",
        "sdks_added", "sdks_removed",
        "native_libs_added", "native_libs_removed", "native_libs_changed",
        "findings_added", "findings_resolved",
    ):
        assert key in body, f"missing key: {key}"
    assert body["a_sha256"] == sha_a
    assert body["b_sha256"] == sha_b
