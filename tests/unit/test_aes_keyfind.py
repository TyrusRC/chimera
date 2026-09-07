"""Recover AES keys by locating their expanded key schedule in memory/bytes.

The scanner is only as trustworthy as the schedule check, so it is pinned with a
FIPS-197 known-answer vector (AES-128) plus 192/256 round-trips, an
embedded-in-noise recovery, and a no-false-positive check on random data.
"""
from __future__ import annotations

import os

from chimera.aes_keyfind import expand_key, find_in_file, find_key_schedules


def test_expand_key_fips197_aes128():
    # FIPS-197 Appendix A.1: key 000102...0f, round-10 key = 13111d7f...30c5
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    sched = expand_key(key)
    assert len(sched) == 176
    assert sched[:16] == key
    assert sched[-16:].hex() == "13111d7fe3944a17f307a78b4d2b30c5"


def test_find_128_192_256_embedded_in_noise():
    for klen, bits in ((16, 128), (24, 192), (32, 256)):
        key = os.urandom(klen)
        blob = b"\x11" * 36 + expand_key(key) + b"\x22" * 40   # word-aligned
        hits = find_key_schedules(blob)
        assert len(hits) == 1, f"{bits}-bit: expected one hit"
        h = hits[0]
        assert h["bits"] == bits
        assert h["key"] == key.hex()
        assert h["offset"] == 36 and h["address"] == 36


def test_iv_candidate_is_bytes_after_schedule():
    key = os.urandom(32)
    iv = os.urandom(16)
    blob = expand_key(key) + iv                    # tiny-AES-c ctx layout
    hits = find_key_schedules(blob)
    assert hits and hits[0]["iv_candidate"] == iv.hex()


def test_no_false_positive_on_random():
    assert find_key_schedules(os.urandom(4096)) == []


def test_longest_match_wins_256_not_128():
    # a real AES-256 schedule's first 176 bytes are NOT a valid 128 schedule,
    # but assert we report it as 256 (largest checked first).
    key = os.urandom(32)
    hits = find_key_schedules(expand_key(key))
    assert len(hits) == 1 and hits[0]["bits"] == 256


def test_find_in_file(tmp_path):
    key = os.urandom(16)
    p = tmp_path / "dump.bin"
    p.write_bytes(b"\x00" * 100 + expand_key(key) + b"\xff" * 64)
    hits = find_in_file(str(p))
    assert hits and hits[0]["key"] == key.hex() and hits[0]["bits"] == 128
