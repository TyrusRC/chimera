"""WS /ws/frida/{session_id} streams messages from the session queue."""
from __future__ import annotations

from dataclasses import dataclass

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
    def on(self, event, h):
        if event == "message": self._on_message = h
    def load(self): self.loaded = True
    def unload(self): self.unloaded = True
    def eval(self, code: str) -> str: return f"<<{code}>>"


class FakeFridaSession:
    def __init__(self):
        self.created_scripts = []
        self.detached = False
    def create_script(self, src):
        s = FakeScript(src); self.created_scripts.append(s); return s
    def detach(self): self.detached = True


@dataclass
class FakeDevice:
    id: str = "emulator-5554"
    resumed: bool = False
    def attach(self, t): return FakeFridaSession()
    def spawn(self, argv): return 1
    def resume(self, pid): self.resumed = True


@pytest.fixture
def client(monkeypatch):
    mgr = get_session_manager()
    for sid in list(mgr.list_session_ids()):
        mgr._sessions.pop(sid, None)
    monkeypatch.setattr(mgr, "_get_device_real", lambda did: FakeDevice(id=did or "x"))
    return TestClient(create_app())


def test_ws_unknown_session_rejects(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/frida/no-such-session") as ws:
            ws.receive_text()


def test_ws_streams_messages_after_eval(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    mgr = get_session_manager()
    # Push a message into the queue as if it came from frida
    mgr.get(sid)._queue.put_nowait({"type": "send", "payload": "hello"})
    with client.websocket_connect(f"/ws/frida/{sid}") as ws:
        msg = ws.receive_json()
        assert msg == {"type": "send", "payload": "hello"}


def test_ws_ping_pong(client):
    sid = client.post("/api/frida/sessions", json={
        "target": "com.example.app", "mode": "attach",
    }).json()["session_id"]
    with client.websocket_connect(f"/ws/frida/{sid}") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"
