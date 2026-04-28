"""Tests for the ObjC callsite linker — pure-logic over r2 xref records."""
from __future__ import annotations


def test_linker_produces_static_callsite_when_class_known():
    from chimera.parsers.macho_objc import link_callsites
    from chimera.model.objc import ObjCMethod

    methods = [ObjCMethod(class_name="LoginVC", selector="auth:",
                          imp_address="0x1abc", is_class_method=False,
                          type_signature=None)]
    # r2 record format: dict per callsite with caller, addr, selector_str,
    # receiver_class (None when dynamic).
    xrefs = [
        {"caller": "0x100456def", "addr": "0x100456e0a",
         "selector": "auth:", "receiver_class": "LoginVC"},
    ]
    callsites = link_callsites(methods, xrefs)
    assert len(callsites) == 1
    cs = callsites[0]
    assert cs.resolution == "static"
    assert cs.receiver_class == "LoginVC"


def test_linker_marks_dynamic_when_receiver_unknown():
    from chimera.parsers.macho_objc import link_callsites

    xrefs = [
        {"caller": "0x100456def", "addr": "0x100456e0a",
         "selector": "auth:", "receiver_class": None},
    ]
    callsites = link_callsites([], xrefs)
    assert len(callsites) == 1
    assert callsites[0].resolution == "dynamic"
    assert callsites[0].receiver_class is None


def test_linker_marks_self_when_receiver_is_self_token():
    from chimera.parsers.macho_objc import link_callsites

    xrefs = [
        {"caller": "0x1", "addr": "0x2", "selector": "x", "receiver_class": "self"},
    ]
    callsites = link_callsites([], xrefs)
    assert callsites[0].resolution == "self"


def test_linker_marks_super_when_receiver_is_super_token():
    from chimera.parsers.macho_objc import link_callsites

    xrefs = [
        {"caller": "0x1", "addr": "0x2", "selector": "x", "receiver_class": "super"},
    ]
    callsites = link_callsites([], xrefs)
    assert callsites[0].resolution == "super"


def test_linker_handles_empty_xrefs():
    from chimera.parsers.macho_objc import link_callsites
    assert link_callsites([], []) == []
