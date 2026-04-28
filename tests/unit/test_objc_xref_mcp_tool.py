"""Tests for the objc_xref MCP tool dispatch."""
from __future__ import annotations

from pathlib import Path

import pytest


def _make_binary_info(p: Path, size: int):
    from chimera.model.binary import (
        Architecture,
        BinaryFormat,
        BinaryInfo,
        Framework,
        Platform,
    )

    return BinaryInfo(
        sha256="0" * 64,
        path=p,
        format=BinaryFormat.IPA,
        platform=Platform.IOS,
        arch=Architecture.ARM64,
        framework=Framework.NATIVE,
        size_bytes=size,
    )


async def test_objc_xref_returns_methods_by_selector(monkeypatch, tmp_path):
    from chimera.model.objc import ObjCCallSite, ObjCMethod
    from chimera.model.program import UnifiedProgramModel

    binary = _make_binary_info(tmp_path / "x.ipa", 0)
    model = UnifiedProgramModel(binary)
    method = ObjCMethod(
        class_name="LoginVC", selector="auth:", imp_address="0x1abc",
        is_class_method=False, type_signature="v",
        enriched_signature="- (BOOL)auth:(NSString *)pw",
    )
    model.add_objc_method(method)
    model.add_objc_callsite(ObjCCallSite(
        caller_function="0xcaller", call_address="0xcall",
        selector="auth:", receiver_class="LoginVC", resolution="static",
    ))

    import chimera.mcp_server as mcp
    monkeypatch.setattr(mcp, "_current_model", model)

    result = await mcp.call_tool("objc_xref", {"selector": "auth:"})
    import json
    payload = json.loads(result[0].text)
    assert "matches" in payload
    assert len(payload["matches"]) == 1
    match = payload["matches"][0]
    assert match["class_name"] == "LoginVC"
    assert match["selector"] == "auth:"
    assert match["enriched_signature"] == "- (BOOL)auth:(NSString *)pw"
    assert len(match["callers"]) == 1


async def test_objc_xref_filters_by_class_when_provided(monkeypatch, tmp_path):
    from chimera.model.objc import ObjCMethod
    from chimera.model.program import UnifiedProgramModel

    binary = _make_binary_info(tmp_path / "x.ipa", 0)
    model = UnifiedProgramModel(binary)
    model.add_objc_method(ObjCMethod(
        class_name="A", selector="x", imp_address="0x1",
        is_class_method=False, type_signature=None,
    ))
    model.add_objc_method(ObjCMethod(
        class_name="B", selector="x", imp_address="0x2",
        is_class_method=False, type_signature=None,
    ))

    import chimera.mcp_server as mcp
    monkeypatch.setattr(mcp, "_current_model", model)

    result = await mcp.call_tool("objc_xref", {"selector": "x", "class_name": "A"})
    import json
    payload = json.loads(result[0].text)
    classes = [m["class_name"] for m in payload["matches"]]
    assert classes == ["A"]


async def test_objc_xref_returns_error_when_no_model(monkeypatch):
    import chimera.mcp_server as mcp
    monkeypatch.setattr(mcp, "_current_model", None)
    import json
    result = await mcp.call_tool("objc_xref", {"selector": "x"})
    payload = json.loads(result[0].text)
    assert "error" in payload
