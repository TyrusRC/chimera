"""Unit tests for SwiftDemangleAdapter — protocol + helper behavior."""

from __future__ import annotations

import asyncio

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


@pytest.mark.asyncio
async def test_demangle_batch_pipes_unique_names_to_stdin(monkeypatch):
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    captured: dict = {}

    class FakeStdin:
        def __init__(self):
            self.data = b""
        def write(self, b: bytes):
            self.data += b
        def close(self):
            captured["stdin"] = self.data
        async def drain(self):
            pass

    class FakeProc:
        returncode = 0
        def __init__(self):
            self.stdin = FakeStdin()
        async def communicate(self, input=None):
            payload = input if input is not None else self.stdin.data
            captured["stdin"] = payload
            mapping = {
                b"_$s4Demo7AppViewC4bodyQrvg": b"Demo.AppView.body.getter : some View",
                b"_T0Foo": b"Foo (Swift 4)",
            }
            stdout_lines = []
            for line in payload.split(b"\n"):
                if not line:
                    continue
                stdout_lines.append(mapping.get(line, line))
            return b"\n".join(stdout_lines) + b"\n", b""

    async def fake_exec(*argv, **kw):
        captured["argv"] = argv
        captured["kwargs"] = kw
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = SwiftDemangleAdapter()
    result = await adapter.demangle_batch([
        "_$s4Demo7AppViewC4bodyQrvg",
        "_T0Foo",
        "_$s4Demo7AppViewC4bodyQrvg",  # duplicate; should be deduped in stdin
    ])

    assert captured["argv"][0] == "swift-demangle"
    assert captured["stdin"].count(b"_$s4Demo7AppViewC4bodyQrvg") == 1
    assert captured["stdin"].count(b"_T0Foo") == 1
    assert result["_$s4Demo7AppViewC4bodyQrvg"] == "Demo.AppView.body.getter : some View"
    assert result["_T0Foo"] == "Foo (Swift 4)"


@pytest.mark.asyncio
async def test_demangle_batch_returns_empty_on_subprocess_failure(monkeypatch):
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    class FakeStdin:
        def write(self, b): pass
        def close(self): pass
        async def drain(self): pass

    class FakeProc:
        returncode = 1
        def __init__(self):
            self.stdin = FakeStdin()
        async def communicate(self, input=None):
            return b"", b"swift-demangle: failure"

    async def fake_exec(*argv, **kw):
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = SwiftDemangleAdapter()
    result = await adapter.demangle_batch(["_$s_irrelevant"])
    assert result == {}


@pytest.mark.asyncio
async def test_demangle_batch_returns_empty_on_oserror(monkeypatch):
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    async def fake_exec(*argv, **kw):
        raise OSError("simulated PATH error")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = SwiftDemangleAdapter()
    result = await adapter.demangle_batch(["_$s_irrelevant"])
    assert result == {}


def test_swift_demangle_is_registered_in_engine(tmp_path):
    """SwiftDemangleAdapter should be registered alongside other adapters."""
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine

    config = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(config)
    adapter = engine.registry.get("swift_demangle")
    assert isinstance(adapter, SwiftDemangleAdapter)
