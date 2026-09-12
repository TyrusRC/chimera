"""On-demand decompile: prefer r2ghidra `pdg`, fall back to r2 `pdc`.

r2 is present in CI/dev; r2ghidra usually is not, so the fallback path (pdc) is
what runs here. We assert the fallback produces C-ish output and reports which
backend was used, and that a forced pdg with no plugin degrades cleanly.
"""
import asyncio
import shutil

import pytest

from chimera.adapters.radare2 import Radare2Adapter

r2_present = shutil.which("r2") or shutil.which("radare2")
pytestmark = pytest.mark.skipif(not r2_present, reason="radare2 not installed")


def _entry(binary):
    a = Radare2Adapter()
    tri = asyncio.run(a.analyze(binary, {"mode": "triage"}))
    # entrypoint or first function address; fall back to a known symbol
    ep = tri.get("entrypoint") or tri.get("entry")
    return a, ep


def test_decompile_falls_back_to_pdc(tmp_path):
    # use a real system binary; decompile its entrypoint
    target = shutil.which("true") or "/bin/true"
    a = Radare2Adapter()
    # entry symbol works without knowing the address
    r = asyncio.run(a.analyze(target, {"mode": "decompile", "address": "entry0"}))
    assert r["ok"] is True, r.get("error")
    assert r["code"].strip()
    # r2ghidra usually absent here → pdc; either way backend is reported
    assert r["backend"] in ("r2ghidra (pdg)", "radare2 (pdc)")


def test_forced_pdg_degrades_cleanly_without_plugin():
    target = shutil.which("true") or "/bin/true"
    a = Radare2Adapter()
    r = asyncio.run(a.analyze(target, {"mode": "decompile", "address": "entry0",
                                       "decompiler": "pdg"}))
    if not r["ok"]:                       # r2ghidra not installed → clean failure + hint
        assert "empty" in r["error"]
        assert "r2ghidra" in r.get("hint", "")
    else:                                 # r2ghidra installed → real pdg output
        assert r["backend"] == "r2ghidra (pdg)"


def test_decompile_needs_address():
    a = Radare2Adapter()
    r = asyncio.run(a.analyze("/bin/true", {"mode": "decompile"}))
    assert r["ok"] is False and "address" in r["error"]
