"""Behavior tests for the MCP write-back handler group.

These assert the thing the read-only surface couldn't do: a tool call
records a finding into the on-disk overlay *and* the live model, and it
comes back on reload. One test per behavior that can actually break.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera import mcp_session as mcpstate
from chimera.core.config import ChimeraConfig
from chimera.core.overlay import ProjectOverlay
from chimera.mcp_handlers import annotations
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel

SHA = "c" * 64
ADDR = "0x140001000"


def _reply(result) -> dict:
    return json.loads("".join(c.text for c in result))


async def _call(name, args):
    return _reply(await annotations.dispatch(name, args))


def _overlay_on_disk() -> ProjectOverlay:
    return ProjectOverlay.load(ChimeraConfig().project_dir, SHA)


@pytest.fixture(autouse=True)
def loaded_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("CHIMERA_PROJECT_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("CHIMERA_CACHE_DIR", str(tmp_path / "cache"))
    # Force the cached engine to rebuild against the tmp env.
    mcpstate.engine = None
    bi = BinaryInfo(
        path=Path("/tmp/fake"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE,
    )
    model = UnifiedProgramModel(bi)
    model.add_function(FunctionInfo(
        address=ADDR, name="FUN_140001000", original_name="FUN_140001000",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    mcpstate.current_model = model
    yield model
    mcpstate.current_model = None
    mcpstate.engine = None


async def test_rename_persists_and_updates_live_model(loaded_binary):
    out = await _call("rename_function", {"address": ADDR, "name": "decode_license"})
    assert out["ok"] and out["model_updated"]
    assert loaded_binary.get_function(ADDR).name == "decode_license"
    assert _overlay_on_disk().get_function_name(ADDR) == "decode_license"


async def test_uppercase_address_normalizes_to_the_function(loaded_binary):
    # An LLM may type 0X... — it must still resolve, not silently miss.
    out = await _call("rename_function", {"address": "0X140001000", "name": "x"})
    assert out["ok"] and out["model_updated"]
    assert loaded_binary.get_function(ADDR).name == "x"


async def test_set_comment_persists(loaded_binary):
    await _call("set_comment", {"address": ADDR, "text": "entry", "line": 0})
    assert _overlay_on_disk().get_comments(ADDR)["0"] == "entry"


async def test_set_type_updates_model_signature(loaded_binary):
    await _call("set_function_type", {"address": ADDR, "signature": "int f(char*)"})
    assert loaded_binary.get_function(ADDR).signature == "int f(char*)"
    assert _overlay_on_disk().get_function_type(ADDR) == "int f(char*)"


async def test_set_classification_updates_model(loaded_binary):
    await _call("set_classification", {"address": ADDR, "classification": "crypto"})
    assert loaded_binary.get_function(ADDR).classification == "crypto"


async def test_add_note_persists(loaded_binary):
    out = await _call("add_note", {"title": "VM key check", "body": "hooks JIT",
                                   "tags": ["writeup"]})
    assert out["ok"] and out["note_id"]
    notes = _overlay_on_disk().list_notes()
    assert len(notes) == 1 and notes[0]["title"] == "VM key check"


async def test_batch_applies_many_in_one_write_and_isolates_a_bad_op(loaded_binary):
    out = await _call("batch_annotate", {"ops": [
        {"op": "rename", "address": ADDR, "name": "checker"},
        {"op": "classify", "address": ADDR, "classification": "license_check"},
        {"op": "comment", "address": ADDR},          # missing text -> error row
    ]})
    assert out["applied"] == 2 and out["total"] == 3
    assert out["results"][2]["ok"] is False
    disk = _overlay_on_disk()
    assert disk.get_function_name(ADDR) == "checker"
    assert disk.user_classifications[ADDR] == "license_check"


async def test_list_annotations_reflects_state(loaded_binary):
    await _call("rename_function", {"address": ADDR, "name": "decode_license"})
    out = await _call("list_annotations", {})
    assert out["function_names"][ADDR] == "decode_license"


async def test_write_without_loaded_binary_errors(monkeypatch):
    mcpstate.current_model = None
    out = _reply(await annotations.dispatch("rename_function",
                                            {"address": ADDR, "name": "x"}))
    assert "error" in out and "analyze" in out["error"].lower()


async def test_rename_of_unknown_address_still_persists_to_overlay(loaded_binary):
    # A stripped .init_array address has no FunctionInfo, but the rename
    # must still be recorded so it isn't lost.
    out = await _call("rename_function", {"address": "0xdeadbeef", "name": "ctor"})
    assert out["ok"] and out["model_updated"] is False
    assert _overlay_on_disk().get_function_name("0xdeadbeef") == "ctor"
