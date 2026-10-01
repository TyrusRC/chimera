"""Tests for the standalone-Ghidra decompile backend (decompiler='ghidra')."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from chimera.adapters.ghidra import GhidraAdapter


def test_decompile_one_script_ships():
    p = Path(__file__).resolve().parents[2] / "src/chimera/ghidra_scripts/DecompileOne.java"
    assert p.exists(), "DecompileOne.java postScript must ship with the package"


def test_ghidra_option_wired_into_cli_and_schema():
    from chimera.mcp_schemas import all_tools
    tool = next(t for t in all_tools() if t.name == "decompile")
    assert "ghidra" in tool.inputSchema["properties"]["decompiler"]["enum"]
    # CLI choice
    from chimera.cli.decompile_cmd import decompile as cmd
    choices = next(p for p in cmd.params if p.name == "decompiler").type.choices
    assert "ghidra" in choices


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="GHIDRA_HOME not set")
@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc required to build the fixture")
def test_ghidra_decompile_one_integration(tmp_path):
    src = tmp_path / "t.c"
    src.write_text("int secret_add(int x,int y){return x*3+y-7;}\nint main(){return secret_add(1,2);}\n")
    exe = tmp_path / "t"
    if subprocess.run(["gcc", "-no-pie", "-O0", "-o", str(exe), str(src)]).returncode != 0:
        pytest.skip("cannot build fixture")
    addr = None
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == "secret_add":
            addr = "0x" + p[0]
    assert addr
    g = GhidraAdapter()
    if not g.is_available():
        pytest.skip("Ghidra not available")
    r = asyncio.run(g.analyze(str(exe), {"mode": "decompile", "address": addr,
                                         "analysis_timeout": 120,
                                         "project_dir": str(tmp_path / "proj")}))
    assert r.get("ok"), r
    assert r["backend"] == "ghidra" and "return" in r["code"] and "* 3" in r["code"]
