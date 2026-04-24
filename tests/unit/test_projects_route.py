"""API project-store behavior."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest


async def test_project_store_is_lock_safe(tmp_path, monkeypatch):
    """Concurrent writes must not corrupt the store."""
    import chimera.api.routes.projects as p

    # Reset module state so test is hermetic
    p._projects.clear()

    async def do_update(i: int):
        await p._store.update(f"k{i}", status=f"s{i}", val=i)

    await asyncio.gather(*[do_update(i) for i in range(100)])
    # All 100 keys present, no key lost to a race
    assert len(p._projects) == 100
    # Each status matches its key
    for i in range(100):
        assert p._projects[f"k{i}"]["status"] == f"s{i}"


async def test_run_analysis_times_out(tmp_path, monkeypatch):
    """A slow analysis must be interrupted by CHIMERA_ANALYSIS_TIMEOUT_SEC."""
    import chimera.api.routes.projects as p
    p._projects.clear()

    # Force a tiny timeout for the test. Because the value is read at module load
    # time, patch the module-level _analysis_timeout directly.
    monkeypatch.setattr(p, "_analysis_timeout", 0.05)

    async def slow_analyze(self, path):
        import asyncio
        await asyncio.sleep(10)
        return None

    # Stub the engine to return a controllable fake. We don't need a real engine.
    from chimera.core.engine import ChimeraEngine
    monkeypatch.setattr(ChimeraEngine, "analyze", slow_analyze)

    # Seed the store as create_project would
    await p._store.set("pid", {"name": "x.apk", "status": "analyzing"})

    class _Req:
        path = "/nonexistent/x.apk"
        ghidra_home = None

    await p._run_analysis("pid", _Req())
    assert "error: timeout" in p._projects["pid"]["status"]
