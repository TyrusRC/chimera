"""x64dbg live-control client: action→endpoint mapping, param forwarding,
response decode, and graceful transport failure. No network — urlopen is
monkeypatched, so nothing needs a live plugin.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from chimera.dynamic import x64dbg as X


class _Resp(io.BytesIO):
    """Minimal stand-in for the urlopen context-manager result."""
    status = 200

    def __init__(self, body: bytes):
        super().__init__(body)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _capture(monkeypatch, body: bytes):
    """Patch urlopen to record the Request it was given and return `body`."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["data"] = req.data
        seen["timeout"] = timeout
        return _Resp(body)

    monkeypatch.setattr(X.urllib.request, "urlopen", fake_urlopen)
    return seen


# ── mapping + params ────────────────────────────────────────────────────────

def test_action_maps_to_endpoint_and_forwards_params(monkeypatch):
    seen = _capture(monkeypatch, b'{"value":"0xdead"}')
    r = X.x64dbg_call("mem_read", {"addr": "0x140001070", "size": "32"})
    assert r["ok"] and r["endpoint"] == "Memory/Read"
    assert r["result"] == {"value": "0xdead"}
    assert seen["method"] == "GET"
    assert seen["url"].startswith("http://127.0.0.1:8888/Memory/Read?")
    assert "addr=0x140001070" in seen["url"] and "size=32" in seen["url"]


def test_none_params_are_dropped(monkeypatch):
    seen = _capture(monkeypatch, b"OK")
    X.x64dbg_call("bp_list", {"type": None})
    assert seen["url"].endswith("/Breakpoint/List")  # no dangling ?type=


def test_text_response_is_returned_as_text(monkeypatch):
    _capture(monkeypatch, b"not-json")
    r = X.x64dbg_call("regs")
    assert r["ok"] and r["text"] == "not-json" and "result" not in r


def test_unknown_action_is_rejected_without_request(monkeypatch):
    # urlopen must never be called for an unknown action
    monkeypatch.setattr(X.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("should not hit the network"))
    r = X.x64dbg_call("frobnicate")
    assert r["ok"] is False and "unknown action" in r["error"]


# ── raw escape hatch ─────────────────────────────────────────────────────────

def test_raw_reaches_arbitrary_endpoint(monkeypatch):
    seen = _capture(monkeypatch, b'{"x":1}')
    r = X.x64dbg_call("raw", {"addr": "0x1000"}, endpoint="Some/New/Endpoint")
    assert r["ok"] and r["endpoint"] == "Some/New/Endpoint"
    assert "Some/New/Endpoint?addr=0x1000" in seen["url"]


def test_raw_without_endpoint_errors(monkeypatch):
    monkeypatch.setattr(X.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("should not hit the network"))
    r = X.x64dbg_call("raw", {})
    assert r["ok"] is False and "needs endpoint" in r["error"]


# ── POST endpoint ────────────────────────────────────────────────────────────

def test_set_page_rights_is_a_post_with_body(monkeypatch):
    seen = _capture(monkeypatch, b"OK")
    X.x64dbg_call("set_page_rights", {"addr": "0x1000", "rights": "ExecuteReadWrite"})
    assert seen["method"] == "POST"
    body = seen["data"].decode()
    assert "addr=0x1000" in body and "rights=ExecuteReadWrite" in body
    assert "?" not in seen["url"]  # params in the body, not the query string


# ── URL resolution ───────────────────────────────────────────────────────────

def test_url_override_and_trailing_slash(monkeypatch):
    seen = _capture(monkeypatch, b"OK")
    X.x64dbg_call("is_debugging", url="http://10.0.0.5:9000")  # no trailing slash
    assert seen["url"] == "http://10.0.0.5:9000/Is_Debugging"


def test_env_url_is_honoured(monkeypatch):
    seen = _capture(monkeypatch, b"OK")
    monkeypatch.setenv("CHIMERA_X64DBG_URL", "http://host:1234/")
    X.x64dbg_call("run")
    assert seen["url"] == "http://host:1234/Debug/Run"


# ── graceful failure (never raises) ──────────────────────────────────────────

def test_transport_failure_returns_error_dict(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(X.urllib.request, "urlopen", boom)
    r = X.x64dbg_call("is_debugging")
    assert r["ok"] is False and "cannot reach x64dbg plugin" in r["error"]


def test_http_error_surfaces_status(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 500, "Server Error", {}, None)
    monkeypatch.setattr(X.urllib.request, "urlopen", boom)
    r = X.x64dbg_call("regs")
    assert r["ok"] is False and r["status"] == 500


def test_every_action_has_a_valid_spec():
    # guards against a typo when the plugin surface grows
    for action, (method, endpoint) in X.ACTIONS.items():
        assert method in ("GET", "POST"), action
        assert endpoint and not endpoint.startswith("/"), action
