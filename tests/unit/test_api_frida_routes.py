"""REST contract tests for /api/frida/*.

These tests use the singleton FridaSessionManager but stub _get_device_real
so no real device or frida binding is needed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient

from chimera.api.server import create_app
from chimera.api.frida_session_manager import get_session_manager


class FakeScript:
    def __init__(self, source: str):
        self.source = source
        self._on_message = None
        self.exports_sync = self
        self.loaded = False
        self.unloaded = False

    def on(self, event, handler):
        if event == "message":
            self._on_message = handler

    def load(self): self.loaded = True
    def unload(self): self.unloaded = True
    def eval(self, code: str) -> str:
        return f"<<{code}>>"


class FakeFridaSession:
    def __init__(self):
        self.created_scripts: list[FakeScript] = []
        self.detached = False

    def create_script(self, source):
        s = FakeScript(source)
        self.created_scripts.append(s)
        return s

    def detach(self): self.detached = True


@dataclass
class FakeDevice:
    id: str = "emulator-5554"
    resumed: bool = False
    def attach(self, target): return FakeFridaSession()
    def spawn(self, argv): return 4242
    def resume(self, pid): self.resumed = True


@pytest.fixture
def client(monkeypatch):
    mgr = get_session_manager()
    # Reset state between tests
    for sid in list(mgr.list_session_ids()):
        mgr._sessions.pop(sid, None)
    monkeypatch.setattr(mgr, "_get_device_real", lambda did: FakeDevice(id=did or "emulator-5554"))
    return TestClient(create_app())


def test_list_scripts_returns_registry(client):
    r = client.get("/api/frida/scripts")
    assert r.status_code == 200
    body = r.json()
    assert "scripts" in body
    assert isinstance(body["scripts"], list)
    if body["scripts"]:
        first = body["scripts"][0]
        assert "id" in first and "name" in first and "platform" in first


def test_create_session_attach_returns_id(client):
    r = client.post("/api/frida/sessions", json={
        "device_id": "emulator-5554",
        "target": "com.example.app",
        "mode": "attach",
    })
    assert r.status_code == 200
    body = r.json()
    assert "session_id" in body and len(body["session_id"]) >= 8


def test_create_session_rejects_bad_mode(client):
    r = client.post("/api/frida/sessions", json={
        "target": "com.example.app",
        "mode": "wrong",
    })
    assert r.status_code == 400


def test_exec_returns_eval_result(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/exec", json={"code": "1+1"})
    assert r.status_code == 200
    assert r.json() == {"result": "<<1+1>>"}


def test_exec_unknown_session_returns_404(client):
    r = client.post("/api/frida/sessions/nonexistent/exec", json={"code": "1"})
    assert r.status_code == 404


def test_load_with_source(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/load", json={"source": "console.log('hi');"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_load_with_script_id_uses_registry(client):
    import chimera.frida_scripts as fs
    scripts = fs.list_scripts()
    if not scripts:
        pytest.skip("no bundled scripts available")
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/load", json={"script_id": scripts[0].id})
    assert r.status_code == 200


def test_load_rejects_both_inputs(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/load", json={
        "source": "x", "script_id": "y",
    })
    assert r.status_code == 400


def test_load_rejects_neither_input(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/load", json={})
    assert r.status_code == 400


def test_load_unknown_script_id_returns_404(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.post(f"/api/frida/sessions/{sid}/load", json={"script_id": "no-such-xyz"})
    assert r.status_code == 404


def test_list_sessions_includes_active(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "spawn",
    }).json()["session_id"]
    r = client.get("/api/frida/sessions")
    assert r.status_code == 200
    body = r.json()
    matching = [s for s in body["sessions"] if s["id"] == sid]
    assert len(matching) == 1
    assert matching[0]["mode"] == "spawn"
    assert matching[0]["target"] == "com.example.app"


def test_close_session(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    r = client.delete(f"/api/frida/sessions/{sid}")
    assert r.status_code == 200
    # subsequent exec should 404
    r = client.post(f"/api/frida/sessions/{sid}/exec", json={"code": "1"})
    assert r.status_code == 404


def test_exec_502_on_underlying_error(client, monkeypatch):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    mgr = get_session_manager()

    async def boom(sid, code):
        raise RuntimeError("frida-server gone")

    monkeypatch.setattr(mgr, "eval_code", boom)
    r = client.post(f"/api/frida/sessions/{sid}/exec", json={"code": "1"})
    assert r.status_code == 502
    assert "frida-server gone" in r.json()["detail"]


def test_load_502_on_underlying_error(client, monkeypatch):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    mgr = get_session_manager()

    async def boom(sid, src):
        raise RuntimeError("script parse failed")

    monkeypatch.setattr(mgr, "load_script", boom)
    r = client.post(f"/api/frida/sessions/{sid}/load", json={"source": "garbage"})
    assert r.status_code == 502
    assert "script parse failed" in r.json()["detail"]
