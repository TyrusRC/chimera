"""MCP server hardening behavior."""
from __future__ import annotations

import pytest


def test_mcp_read_cache_rejects_unknown_category():
    import chimera.mcp_session as m
    # category whitelist enforcement: arbitrary strings must be rejected
    allowed = m._ALLOWED_CACHE_CATEGORIES
    assert "triage" in allowed
    # Pick a category guaranteed NOT to be in the whitelist
    assert not m.is_allowed_category("../etc/passwd")
    assert not m.is_allowed_category("not_a_real_category")
    # Known-good prefixes still allowed
    assert m.is_allowed_category("triage")
    assert m.is_allowed_category("r2_libfoo.so")
    assert m.is_allowed_category("ghidra_main")


async def test_read_cache_disallowed_category_returns_error_not_nameerror():
    # Regression: the read_cache error branch referenced _ALLOWED_CACHE_* names
    # that live in mcp_session but were never imported into the artifacts
    # handler, so a disallowed category raised NameError instead of the
    # intended allow-list error message.
    import chimera.mcp_session as m
    from chimera.mcp_handlers import artifacts

    m.current_model = object()          # make require_model() pass
    try:
        res = await artifacts.dispatch("read_cache", {"category": "definitely_not_allowed"})
    finally:
        m.current_model = None
    assert res is not None
    assert "allow-list" in res[0].text


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
