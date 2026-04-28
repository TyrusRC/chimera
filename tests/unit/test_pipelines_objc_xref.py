"""Tests for the Phase 4.5 ObjC cross-reference orchestrator."""
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


async def test_phase_4_5_skips_non_macho_binary(tmp_path):
    from chimera.model.program import UnifiedProgramModel
    from chimera.pipelines.objc_xref import build_objc_xref

    p = tmp_path / "fake.bin"
    p.write_bytes(b"PK\x03\x04")  # ZIP magic, not Mach-O
    binary = _make_binary_info(p, 4)
    model = UnifiedProgramModel(binary)
    ctx = await build_objc_xref(
        model=model, main_binary=p,
        class_dump_json=None, r2_xrefs=[],
    )
    assert ctx["available"] is False
    assert ctx["skipped_reason"] == "not_macho"
    assert ctx["class_count"] == 0


async def test_phase_4_5_populates_model_from_synthetic_dylib(tmp_path):
    from chimera.model.program import UnifiedProgramModel
    from chimera.pipelines.objc_xref import build_objc_xref
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    raw = build_macho_with_objc(
        classes=[BuilderClass(
            name="LoginVC", superclass="NSObject",
            methods=[BuilderMethod(selector="auth:",
                                    types="v16@0:8",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    p = tmp_path / "syn.dylib"
    p.write_bytes(raw)
    binary = _make_binary_info(p, len(raw))
    model = UnifiedProgramModel(binary)

    ctx = await build_objc_xref(
        model=model, main_binary=p,
        class_dump_json=None, r2_xrefs=[],
    )
    assert ctx["available"] is True
    assert ctx["class_count"] == 1
    assert ctx["method_count"] == 1
    assert any(m.selector == "auth:" for m in model.objc_methods)
    assert any(c.name == "LoginVC" for c in model.objc_classes)


async def test_phase_4_5_enriches_with_class_dump_json(tmp_path):
    from chimera.model.program import UnifiedProgramModel
    from chimera.pipelines.objc_xref import build_objc_xref
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    raw = build_macho_with_objc(
        classes=[BuilderClass(
            name="LoginVC", superclass="NSObject",
            methods=[BuilderMethod(selector="auth:",
                                    types="v16@0:8",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    p = tmp_path / "syn.dylib"
    p.write_bytes(raw)
    binary = _make_binary_info(p, len(raw))
    model = UnifiedProgramModel(binary)

    cd_json = {
        "classes": [{
            "name": "LoginVC",
            "instance_methods": [{
                "selector": "auth:",
                "human_signature": "- (BOOL)auth:(NSString *)password",
            }],
        }]
    }
    ctx = await build_objc_xref(
        model=model, main_binary=p,
        class_dump_json=cd_json, r2_xrefs=[],
    )
    assert ctx["class_dump_enriched"] is True
    method = next(m for m in model.objc_methods if m.selector == "auth:")
    assert method.enriched_signature == "- (BOOL)auth:(NSString *)password"


async def test_phase_4_5_records_callsites_from_r2_xrefs(tmp_path):
    from chimera.model.program import UnifiedProgramModel
    from chimera.pipelines.objc_xref import build_objc_xref
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    raw = build_macho_with_objc(
        classes=[BuilderClass(
            name="LoginVC", superclass="NSObject",
            methods=[BuilderMethod(selector="auth:", types="v",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    p = tmp_path / "syn.dylib"
    p.write_bytes(raw)
    binary = _make_binary_info(p, len(raw))
    model = UnifiedProgramModel(binary)
    xrefs = [
        {"caller": "0x100456def", "addr": "0x100456e0a",
         "selector": "auth:", "receiver_class": "LoginVC"},
    ]
    ctx = await build_objc_xref(
        model=model, main_binary=p,
        class_dump_json=None, r2_xrefs=xrefs,
    )
    assert ctx["callsite_count"] == 1
    assert ctx["callsites_resolved_static"] == 1
    assert len(model.objc_callsites) == 1
