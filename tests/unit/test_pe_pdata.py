"""x64 .pdata function recovery + ILT thunk resolution.

On a `/INCREMENTAL`-linked MSVC PE64 every internal call routes through an
Incremental Link Table of `jmp` thunks, which defeats r2's `aaa` call-graph
discovery — it silently reports roughly the import count instead of the real
function count. The authoritative count lives in the `.pdata` exception
directory (one RUNTIME_FUNCTION per real function). These are pure helpers over
raw bytes, so the tests build the bytes directly.
"""
from __future__ import annotations

import struct

from chimera.parsers.pe_pdata import (
    count_looks_bogus,
    parse_pdata_entries,
    resolve_thunk,
)

IMAGE_BASE = 0x140000000


def _rf(begin, end, unwind):
    return struct.pack("<III", begin, end, unwind)


def test_parse_pdata_entries_yields_function_starts():
    pdata = _rf(0x3274, 0x3280, 0x1000) + _rf(0xACB0, 0xAD00, 0x1010)
    fns = parse_pdata_entries(pdata, IMAGE_BASE)
    assert [f["start"] for f in fns] == [0x140003274, 0x14000ACB0]
    assert fns[0]["end"] == 0x140003280


def test_parse_pdata_entries_skips_zero_padding():
    pdata = _rf(0xACB0, 0xAD00, 0x1010) + _rf(0, 0, 0)
    fns = parse_pdata_entries(pdata, IMAGE_BASE)
    assert len(fns) == 1 and fns[0]["start"] == 0x14000ACB0


def test_parse_pdata_entries_ignores_trailing_partial_row():
    pdata = _rf(0xACB0, 0xAD00, 0x1010) + b"\x01\x02\x03"  # 3 stray bytes
    assert len(parse_pdata_entries(pdata, IMAGE_BASE)) == 1


def test_resolve_thunk_follows_jmp_rel32():
    # jmp rel32: E9 <rel32>; target = va + 5 + rel
    code = b"\xe9\x08\x00\x00\x00"
    assert resolve_thunk(code, 0x140003274) == 0x140003274 + 5 + 8


def test_resolve_thunk_handles_negative_rel():
    rel = -0x20
    code = b"\xe9" + struct.pack("<i", rel)
    assert resolve_thunk(code, 0x140004000) == 0x140004000 + 5 - 0x20


def test_resolve_thunk_none_for_non_jmp():
    assert resolve_thunk(b"\x48\x89\x4c\x24\x08", 0x1000) is None


def test_count_looks_bogus_flags_import_count_masquerade():
    # r2 reported 112 == import count; .pdata proves 3497 real functions.
    assert count_looks_bogus(r2_count=112, import_count=112, pdata_count=3497)


def test_count_looks_bogus_false_when_r2_found_real_functions():
    assert not count_looks_bogus(r2_count=3000, import_count=112, pdata_count=3497)


def test_count_looks_bogus_false_without_pdata():
    assert not count_looks_bogus(r2_count=5, import_count=112, pdata_count=0)
