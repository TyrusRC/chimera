"""Sanity tests for Mach-O / ObjC struct format-string sizes."""
from __future__ import annotations


def test_class_t_size_matches_apple_layout():
    """objc_class_t is 5 pointers (40 bytes on 64-bit)."""
    from chimera.parsers.macho_objc_structs import CLASS_T

    assert CLASS_T.size == 40  # 5 × 8


def test_class_ro_t_size_matches_apple_layout():
    """class_ro_t: flags(4) instanceStart(4) instanceSize(4) reserved(4) ivarLayout(8) name(8) baseMethods(8) baseProtocols(8) ivars(8) weakIvarLayout(8) baseProperties(8)."""
    from chimera.parsers.macho_objc_structs import CLASS_RO_T

    assert CLASS_RO_T.size == 72


def test_method_t_size_is_three_pointers():
    """method_t: name(8) types(8) imp(8) = 24 bytes (large/64-bit form)."""
    from chimera.parsers.macho_objc_structs import METHOD_T

    assert METHOD_T.size == 24


def test_method_list_header_size():
    """method_list_t header: entsize_and_flags(4) count(4)."""
    from chimera.parsers.macho_objc_structs import METHOD_LIST_HEADER

    assert METHOD_LIST_HEADER.size == 8


def test_category_t_size_matches_apple_layout():
    """category_t: name(8) cls(8) instanceMethods(8) classMethods(8) protocols(8) instanceProperties(8)."""
    from chimera.parsers.macho_objc_structs import CATEGORY_T

    assert CATEGORY_T.size == 48


def test_chained_fixup_constants_present():
    from chimera.parsers.macho_objc_structs import (
        DYLD_CHAINED_PTR_64,
        DYLD_CHAINED_PTR_64_OFFSET,
        DYLD_CHAINED_PTR_ARM64E,
        LC_DYLD_CHAINED_FIXUPS,
    )

    assert LC_DYLD_CHAINED_FIXUPS == 0x80000034
    assert DYLD_CHAINED_PTR_ARM64E == 1
    assert DYLD_CHAINED_PTR_64 == 2
    assert DYLD_CHAINED_PTR_64_OFFSET == 6


def test_arm64e_pac_strip_mask():
    from chimera.parsers.macho_objc_structs import strip_pac

    assert strip_pac(0x80000001000123ab) == 0x000000001000123ab
    assert strip_pac(0x100123ab) == 0x100123ab  # already-clean low pointer
