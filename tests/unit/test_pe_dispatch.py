"""Dispatch-table recovery.

The pure core `scan_pointer_arrays` is where the logic lives (run detection,
strict validation, RVA mapping, alignment), so it is pinned hard on hand-built
byte buffers. `find_dispatch_tables`/`disassemble_many` are thin pefile/capstone
wrappers — smoke-checked only, since a hand-forged PE would buy false confidence.
"""
from __future__ import annotations

import struct

from chimera.parsers.pe_dispatch import scan_pointer_arrays

BASE = 0x140000000


def _va_array(vas, ptr_size=8):
    fmt = "<Q" if ptr_size == 8 else "<I"
    return b"".join(struct.pack(fmt, v) for v in vas)


def test_detects_run_of_valid_va_pointers():
    targets = {BASE + 0x1000 + i * 0x10 for i in range(8)}
    noise = b"\x11" * 24                      # 3 junk 8-byte words up front
    arr = _va_array(sorted(targets))
    data = noise + arr + b"\x22" * 16
    hits = scan_pointer_arrays(data, BASE, targets, min_run=8)
    assert len(hits) == 1
    h = hits[0]
    assert h["offset"] == 24                  # right after the noise
    assert h["base_va"] == BASE + 24
    assert h["count"] == 8
    assert h["kind"] == "va" and h["ptr_size"] == 8


def test_accepts_callable_predicate_range_check():
    # validate "points into an executable section" via a range predicate — the
    # form find_dispatch_tables uses so a generated FSM's non-.pdata handlers
    # still register. Entries are RVAs into a fake .text at [0x1000, 0x2000).
    lo, hi = BASE + 0x1000, BASE + 0x2000
    rvas = [0x1000 + i * 4 for i in range(10)]        # all map into [lo,hi)
    data = _va_array(rvas, ptr_size=4)
    in_exec = lambda va: lo <= va < hi                # noqa: E731
    hits = scan_pointer_arrays(data, BASE, in_exec, ptr_size=4, is_rva=True,
                               image_base=BASE, min_run=8)
    assert len(hits) == 1 and hits[0]["count"] == 10 and hits[0]["kind"] == "rva"


def test_run_shorter_than_min_run_ignored():
    targets = {BASE + i * 8 for i in range(4)}
    data = _va_array(sorted(targets))          # only 4 entries
    assert scan_pointer_arrays(data, BASE, targets, min_run=8) == []
    # but a lower threshold accepts it
    hits = scan_pointer_arrays(data, BASE, targets, min_run=4)
    assert hits and hits[0]["count"] == 4


def test_rva_mode_maps_and_detects():
    image_base = BASE
    rvas = [0x2000 + i * 0x8 for i in range(10)]
    targets = {image_base + r for r in rvas}
    data = _va_array(rvas, ptr_size=4)
    hits = scan_pointer_arrays(
        data, image_base, targets,
        ptr_size=4, is_rva=True, image_base=image_base, min_run=8,
    )
    assert len(hits) == 1
    assert hits[0]["count"] == 10
    assert hits[0]["kind"] == "rva" and hits[0]["ptr_size"] == 4


def test_one_bad_entry_splits_into_two_runs():
    # 10 valid, one junk, 10 valid  → two runs of 10 (strict: a miss ends a run)
    left = [BASE + 0x100 + i * 8 for i in range(10)]
    right = [BASE + 0x500 + i * 8 for i in range(10)]
    targets = set(left) | set(right)
    data = _va_array(left) + struct.pack("<Q", 0xDEAD) + _va_array(right)
    hits = scan_pointer_arrays(data, BASE, targets, min_run=8)
    assert [h["count"] for h in hits] == [10, 10]
    # second run starts after 10 entries + 1 junk word = 88 bytes
    assert hits[1]["offset"] == (10 + 1) * 8


def test_no_targets_no_hits():
    data = _va_array([BASE + i * 8 for i in range(20)])
    assert scan_pointer_arrays(data, BASE, set(), min_run=8) == []
