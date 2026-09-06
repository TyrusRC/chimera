"""Pagination / bounded-output tests for heavy MCP query tools.

These exist because an unbounded list or a runaway callgraph walk blows
up the driving model's context — most damaging when a small model is at
the wheel. Each test asserts the bound actually bounds.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera import mcp_session as mcpstate
from chimera.mcp_handlers import analysis, artifacts
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel


def _reply(result) -> dict:
    return json.loads("".join(c.text for c in result))


@pytest.fixture
def model(monkeypatch, tmp_path):
    monkeypatch.setenv("CHIMERA_PROJECT_DIR", str(tmp_path / "p"))
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "c"))
    mcpstate.engine = None
    bi = BinaryInfo(
        path=Path("/tmp/fake"), sha256="d" * 64, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    mcpstate.current_model = m
    yield m
    mcpstate.current_model = None
    mcpstate.engine = None


async def test_get_strings_pages_with_offset_and_has_more(model):
    for i in range(250):
        model.add_string(f"0x{i:x}", f"str{i}")
    first = _reply(await analysis.dispatch("get_strings", {"limit": 100, "offset": 0}))
    assert first["total"] == 250 and first["has_more"] is True
    assert len(first["strings"]) == 100
    last = _reply(await analysis.dispatch("get_strings", {"limit": 100, "offset": 200}))
    assert last["has_more"] is False and len(last["strings"]) == 50


async def test_get_disassembly_is_bounded(model):
    f = FunctionInfo(address="0x1000", name="big", original_name="big",
                     language="asm", classification="unknown", layer="native",
                     source_backend="r2")
    f.disassembly = [f"insn{i}" for i in range(1000)]
    model.add_function(f)
    out = _reply(await artifacts.dispatch("get_disassembly",
                                          {"address": "0x1000", "limit": 200}))
    assert out["instruction_count"] == 1000
    assert len(out["instructions"]) == 200 and out["has_more"] is True


async def test_get_callgraph_caps_nodes_and_flags_truncation(model):
    # A linear chain of 50 functions, each calling the next.
    for i in range(50):
        model.add_function(FunctionInfo(
            address=f"0x{i:x}", name=f"f{i}", original_name=f"f{i}",
            language="c", classification="unknown", layer="native",
            source_backend="r2"))
    for i in range(49):
        model.add_call_edge(f"0x{i:x}", f"0x{i+1:x}")
    out = _reply(await analysis.dispatch(
        "get_callgraph", {"address": "0x0", "depth": 10, "max_nodes": 10}))
    assert len(out["nodes"]) <= 10 and out["truncated"] is True
