"""Tests for ObjC model entities + UnifiedProgramModel additions."""
from __future__ import annotations

from pathlib import Path


def _make_ios_binary():
    from chimera.model.binary import (
        Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
    )
    return BinaryInfo(
        sha256="0" * 64, path=Path("/tmp/x.ipa"),
        format=BinaryFormat.IPA, platform=Platform.IOS,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=0,
    )


def test_objc_method_dataclass_shape():
    from chimera.model.objc import ObjCMethod

    m = ObjCMethod(
        class_name="LoginVC",
        selector="authenticate:",
        imp_address="0x100123abc",
        is_class_method=False,
        type_signature="v16@0:8",
    )
    assert m.class_name == "LoginVC"
    assert m.selector == "authenticate:"
    assert m.category is None
    assert m.declared_in_protocol == []
    assert m.enriched_signature is None


def test_objc_callsite_dataclass_shape():
    from chimera.model.objc import ObjCCallSite

    cs = ObjCCallSite(
        caller_function="0x100456def",
        call_address="0x100456e0a",
        selector="authenticate:",
        receiver_class="LoginVC",
        resolution="static",
    )
    assert cs.resolution == "static"
    assert cs.receiver_class == "LoginVC"


def test_objc_class_collects_methods_and_protocols():
    from chimera.model.objc import ObjCClass, ObjCMethod

    m1 = ObjCMethod(class_name="C", selector="a", imp_address="0x1",
                    is_class_method=False, type_signature=None)
    cls = ObjCClass(
        name="C",
        superclass="NSObject",
        instance_methods=[m1],
        class_methods=[],
        protocols=["FooProtocol"],
        categories=[],
        is_swift_objc=False,
    )
    assert len(cls.instance_methods) == 1
    assert "FooProtocol" in cls.protocols


def test_swift_objc_flag_detection():
    from chimera.model.objc import ObjCClass

    cls = ObjCClass(
        name="_$s4Demo7AppViewC",
        superclass=None,
        instance_methods=[],
        class_methods=[],
        protocols=[],
        categories=[],
        is_swift_objc=True,
    )
    assert cls.is_swift_objc is True


def test_unified_model_add_objc_method_and_lookup():
    from chimera.model.objc import ObjCMethod
    from chimera.model.program import UnifiedProgramModel

    model = UnifiedProgramModel(_make_ios_binary())
    m = ObjCMethod(class_name="C", selector="a:", imp_address="0x1",
                   is_class_method=False, type_signature=None)
    model.add_objc_method(m)

    found = model.find_objc_method(class_name="C", selector="a:")
    assert found == [m]

    found_any = model.find_objc_method(class_name=None, selector="a:")
    assert m in found_any


def test_unified_model_add_objc_callsite_and_callers():
    from chimera.model.objc import ObjCCallSite
    from chimera.model.program import UnifiedProgramModel

    model = UnifiedProgramModel(_make_ios_binary())
    cs = ObjCCallSite(
        caller_function="0xabc", call_address="0xabd", selector="a:",
        receiver_class="C", resolution="static",
    )
    model.add_objc_callsite(cs)
    callers = model.find_objc_callers(imp_address="0x1")
    # No method registered at 0x1 => no callers found
    assert callers == []

    from chimera.model.objc import ObjCMethod
    model.add_objc_method(ObjCMethod(
        class_name="C", selector="a:", imp_address="0x1",
        is_class_method=False, type_signature=None,
    ))
    callers = model.find_objc_callers(imp_address="0x1")
    assert callers == [cs]
