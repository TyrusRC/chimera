"""Mach-O ObjC parser unit tests."""
from __future__ import annotations

import pytest


def test_parser_returns_empty_when_no_classlist_section(tmp_path):
    """A Mach-O without __objc_classlist returns empty metadata, no exception."""
    from chimera.parsers.macho_objc import parse_objc_metadata
    from tests.unit._macho_builder import build_macho_with_objc

    raw = build_macho_with_objc(classes=[], categories=[], protocols=[])
    p = tmp_path / "empty.dylib"
    p.write_bytes(raw)

    md = parse_objc_metadata(p)
    assert md.classes == []
    assert md.categories == []
    assert md.protocols == []
    assert md.chained_fixups_detected is False


def test_parser_finds_one_class_with_one_method(tmp_path):
    """Single class + single method round-trips through the parser."""
    from chimera.parsers.macho_objc import parse_objc_metadata
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    raw = build_macho_with_objc(
        classes=[BuilderClass(
            name="LoginVC", superclass="NSObject",
            methods=[BuilderMethod(selector="authenticate:",
                                    types="v16@0:8",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    p = tmp_path / "one.dylib"
    p.write_bytes(raw)

    md = parse_objc_metadata(p)
    assert len(md.classes) == 1
    cls = md.classes[0]
    assert cls.name == "LoginVC"
    assert cls.superclass == "NSObject"
    assert len(cls.instance_methods) == 1
    m = cls.instance_methods[0]
    assert m.class_name == "LoginVC"
    assert m.selector == "authenticate:"
    assert m.imp_address == "0x100123abc"
    assert m.type_signature == "v16@0:8"
    assert m.is_class_method is False


@pytest.mark.xfail(reason="metaclass parsing implemented in Task 5", strict=True)
def test_parser_handles_class_with_class_methods(tmp_path):
    """A class with both instance and class methods returns both lists."""
    from chimera.parsers.macho_objc import parse_objc_metadata
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    raw = build_macho_with_objc(
        classes=[BuilderClass(
            name="C", superclass="NSObject",
            methods=[BuilderMethod(selector="i:", types="v16@0:8", imp_addr=0x1)],
            class_methods=[BuilderMethod(selector="c:", types="v16@0:8", imp_addr=0x2)],
        )],
        categories=[], protocols=[],
    )
    p = tmp_path / "cm.dylib"
    p.write_bytes(raw)

    md = parse_objc_metadata(p)
    cls = md.classes[0]
    assert [m.selector for m in cls.instance_methods] == ["i:"]
    assert [m.selector for m in cls.class_methods] == ["c:"]
    assert cls.class_methods[0].is_class_method is True
