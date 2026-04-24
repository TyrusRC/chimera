"""MCP server hardening behavior."""
from __future__ import annotations

import pytest


def test_mcp_read_cache_rejects_unknown_category():
    import chimera.mcp_server as m
    # category whitelist enforcement: arbitrary strings must be rejected
    allowed = m._ALLOWED_CACHE_CATEGORIES
    assert "triage" in allowed
    # Pick a category guaranteed NOT to be in the whitelist
    assert not m._is_allowed_category("../etc/passwd")
    assert not m._is_allowed_category("not_a_real_category")
    # Known-good prefixes still allowed
    assert m._is_allowed_category("triage")
    assert m._is_allowed_category("r2_libfoo.so")
    assert m._is_allowed_category("ghidra_main")


def test_frida_adapter_exposes_active_sessions():
    from chimera.adapters.frida_adapter import FridaAdapter
    adapter = FridaAdapter()
    assert adapter.active_sessions() == []
    # Populate internal state directly (we own this adapter's lifecycle in the test)
    adapter._sessions["com.example.a"] = object()
    adapter._sessions["com.example.b"] = object()
    sessions = adapter.active_sessions()
    assert isinstance(sessions, list)
    assert set(sessions) == {"com.example.a", "com.example.b"}
