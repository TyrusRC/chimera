"""MCP detect_protections must fold in the native PE/ELF profile.

The mobile string detector never sees a PE/ELF import table, so on a
native (incl. .NET) target it misses anti-debug imports like
CheckRemoteDebuggerPresent. The handler reads the pipeline's cached
`native_protection` and merges it — this pins that behaviour.
"""
from __future__ import annotations

import asyncio
import json
import types

import pytest

from chimera import mcp_session as mcpstate
from chimera.mcp_handlers import analysis


class _FakeBinary:
    sha256 = "deadbeef"
    class platform:  # noqa: N801
        value = "windows"


class _FakeModel:
    binary = _FakeBinary()
    def get_strings(self):
        return []


class _FakeCache:
    def get_json(self, sha, key):
        if key == "native_protection":
            return {"has_anti_debug": True,
                    "details": ["anti_debug strings: CheckRemoteDebuggerPresent"]}
        return None


def test_detect_protections_merges_native_anti_debug(monkeypatch):
    monkeypatch.setattr(mcpstate, "current_model", _FakeModel())
    fake_engine = types.SimpleNamespace(cache=_FakeCache())
    monkeypatch.setattr(mcpstate, "get_engine", lambda: fake_engine)

    result = asyncio.run(analysis.dispatch("detect_protections", {}))
    payload = json.loads(result[0].text)
    assert payload["anti_debug"] is True
    assert payload["has_any_protection"] is True
