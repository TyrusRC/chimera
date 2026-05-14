"""GET /api/projects/{id} includes a `capabilities` block describing which
analyst surfaces (Frida, MASVS, manifest, network-security-config) apply to
the binary's format."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from chimera.api.routes.projects import _capabilities_for, _store
from chimera.api.server import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.mark.asyncio
async def test_capabilities_apk_enables_mobile_surfaces(client):
    await _store.set("test-apk", {
        "name": "x.apk", "path": "/x.apk", "platform": "android",
        "format": "apk", "framework": "java",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    r = client.get("/api/projects/test-apk")
    assert r.status_code == 200
    caps = r.json()["capabilities"]
    assert caps["frida"] is True
    assert caps["masvs"] is True
    assert caps["manifest"] is True
    assert caps["network_security_config"] is True
    assert caps["objc"] is False
    assert caps["dotnet"] is False


@pytest.mark.asyncio
async def test_capabilities_ipa_enables_frida_objc_no_manifest(client):
    await _store.set("test-ipa", {
        "name": "x.ipa", "path": "/x.ipa", "platform": "ios",
        "format": "ipa", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    caps = client.get("/api/projects/test-ipa").json()["capabilities"]
    assert caps["frida"] is True
    assert caps["masvs"] is True
    assert caps["manifest"] is False
    assert caps["network_security_config"] is False
    assert caps["objc"] is True


@pytest.mark.asyncio
async def test_capabilities_pe_disables_mobile_surfaces(client):
    await _store.set("test-pe", {
        "name": "x.exe", "path": "/x.exe", "platform": "windows",
        "format": "pe64", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    caps = client.get("/api/projects/test-pe").json()["capabilities"]
    assert caps["frida"] is False
    assert caps["masvs"] is False
    assert caps["manifest"] is False
    assert caps["network_security_config"] is False
    assert caps["objc"] is False


@pytest.mark.asyncio
async def test_capabilities_macho_enables_objc_no_manifest(client):
    await _store.set("test-macho", {
        "name": "x.dylib", "path": "/x.dylib", "platform": "ios",
        "format": "dylib", "framework": "native",
        "function_count": 0, "string_count": 0, "status": "complete",
    })
    caps = client.get("/api/projects/test-macho").json()["capabilities"]
    # Bare Mach-O / dylib is not an installable app — no Frida UI, but ObjC tab applies.
    assert caps["frida"] is False
    assert caps["masvs"] is False
    assert caps["objc"] is True


def test_capabilities_for_unknown_format_all_false():
    caps = _capabilities_for(None)
    assert all(v is False for v in caps.values())
    caps2 = _capabilities_for("widget")
    assert all(v is False for v in caps2.values())
