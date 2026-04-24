"""FastAPI app-level behavior."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_default_cors_allows_localhost_any_port(monkeypatch):
    monkeypatch.delenv("CHIMERA_CORS_ORIGINS", raising=False)
    # Rebuild the app so the env-absent branch is taken
    import importlib
    import chimera.api.server as srv_mod
    importlib.reload(srv_mod)
    client = TestClient(srv_mod.app)

    r = client.options(
        "/api/info",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code in (200, 204), r.status_code
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_explicit_cors_env_uses_literal_allowlist(monkeypatch):
    monkeypatch.setenv("CHIMERA_CORS_ORIGINS", "https://example.com,https://other.com")
    import importlib
    import chimera.api.server as srv_mod
    importlib.reload(srv_mod)
    client = TestClient(srv_mod.app)

    r = client.options(
        "/api/info",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code in (200, 204)
    assert r.headers.get("access-control-allow-origin") == "https://example.com"

    r = client.options(
        "/api/info",
        headers={
            "Origin": "https://not-allowed.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Not in allowlist -> no CORS header granted
    assert r.headers.get("access-control-allow-origin") != "https://not-allowed.com"
