"""Self-tests for the synthetic Mach-O builder used by parser unit tests."""
from __future__ import annotations

import pytest


def test_builder_emits_structurally_valid_macho_with_three_objc_sections():
    """Walk the synthesized Mach-O headers without using the Task-4 parser."""
    from chimera.parsers.macho_objc_structs import (
        MACH_HEADER_64, LOAD_COMMAND, SEGMENT_COMMAND_64, SECTION_64,
    )
    from tests.unit._macho_builder import build_macho_with_objc

    raw = build_macho_with_objc(classes=[], categories=[], protocols=[])

    # Header is parseable.
    magic, _ct, _st, _ft, ncmds, sizeofcmds, _fl, _r = MACH_HEADER_64.unpack_from(raw, 0)
    assert magic == 0xfeedfacf
    assert ncmds == 1

    # Single LC_SEGMENT_64 with three sections, all named __objc_*.
    cmd, cmdsize = LOAD_COMMAND.unpack_from(raw, MACH_HEADER_64.size)
    assert cmd == 0x19  # LC_SEGMENT_64
    assert cmdsize == sizeofcmds  # only one cmd, so its size == total

    seg = SEGMENT_COMMAND_64.unpack_from(raw, MACH_HEADER_64.size)
    nsects = seg[9]
    assert nsects == 3

    # Each section header decodes; sectnames are the three __objc_* sections.
    sect_off = MACH_HEADER_64.size + SEGMENT_COMMAND_64.size
    sect_names = []
    for _ in range(nsects):
        section = SECTION_64.unpack_from(raw, sect_off)
        sect_names.append(section[0].rstrip(b"\0").decode())
        sect_off += SECTION_64.size
    assert set(sect_names) == {"__objc_classlist", "__objc_catlist", "__objc_protolist"}


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
