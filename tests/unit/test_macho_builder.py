"""Self-tests for the synthetic Mach-O builder used by parser unit tests."""
from __future__ import annotations

import pytest


def test_builder_produces_valid_macho_magic():
    from tests.unit._macho_builder import build_macho_with_objc

    raw = build_macho_with_objc(classes=[], categories=[], protocols=[])
    # 64-bit Mach-O magic, little-endian: 0xfeedfacf
    assert raw[:4] == b"\xcf\xfa\xed\xfe"


@pytest.mark.xfail(reason="parser landed in Task 4", strict=True)
def test_builder_round_trips_one_class_with_one_method():
    from tests.unit._macho_builder import build_macho_with_objc, BuilderClass, BuilderMethod

    raw = build_macho_with_objc(
        classes=[BuilderClass(name="LoginVC", superclass="NSObject",
                              methods=[BuilderMethod(selector="auth:",
                                                     types="v16@0:8",
                                                     imp_addr=0x1000)])],
        categories=[],
        protocols=[],
    )
    # Expect classlist section to contain 1 entry.
    from chimera.parsers.macho_objc import _read_section_bytes  # introduced Task 4
    classlist = _read_section_bytes(raw, "__DATA_CONST", "__objc_classlist")
    assert len(classlist) == 8  # one 64-bit pointer
