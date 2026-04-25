"""Unit tests for SwiftDemangleAdapter — protocol + helper behavior."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest


def test_swift_demangle_adapter_metadata():
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    a = SwiftDemangleAdapter()
    assert a.name() == "swift_demangle"
    assert "text" in a.supported_formats()


def test_mangled_regex_matches_swift_5_and_swift_4():
    from chimera.adapters.swift_demangle import _MANGLED_RE

    assert _MANGLED_RE.match("_$s4Demo7AppViewC4bodyQrvg") is not None
    assert _MANGLED_RE.match("_$S4Demo7AppViewC4bodyQrvg") is not None
    assert _MANGLED_RE.match("_T0__T_Foo") is not None
    assert _MANGLED_RE.match("_TtFoo") is not None
    assert _MANGLED_RE.match("regular_function_name") is None
    assert _MANGLED_RE.match("printf") is None
    assert _MANGLED_RE.match("") is None


def test_mangled_token_regex_finds_mangled_in_text():
    from chimera.adapters.swift_demangle import _MANGLED_TOKEN_RE

    body = "void demo() { _$s4Demo7AppViewC4bodyQrvg(); other(); _T0Foo bar; }"
    matches = [m.group(0) for m in _MANGLED_TOKEN_RE.finditer(body)]
    assert "_$s4Demo7AppViewC4bodyQrvg" in matches
    assert "_T0Foo" in matches
    assert "demo" not in matches


@pytest.mark.asyncio
async def test_demangle_batch_empty_input_returns_empty_dict_no_subprocess(monkeypatch):
    """Empty input must not spawn a subprocess."""
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    spawn_calls: list = []

    async def fake_exec(*argv, **kw):
        spawn_calls.append(argv)
        raise AssertionError("subprocess should not be spawned for empty input")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = SwiftDemangleAdapter()
    result = await adapter.demangle_batch([])
    assert result == {}
    assert spawn_calls == []
