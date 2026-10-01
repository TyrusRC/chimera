"""Tests for crypto_triage (keystream-reuse detector + crib-drag)."""
from __future__ import annotations

import os

from chimera import crypto_triage as ct


def _ks(n, seed=1234):
    import random
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def test_detects_reuse_with_shared_keystream():
    ks = _ks(200)
    p1 = b"HEADERv1 the quick brown fox jumps over the lazy dog, and then some." + b" " * 130
    p2 = b"HEADERv1 pack my box with five dozen liquor jugs for the big party!!" + b" " * 130
    c1 = bytes(a ^ b for a, b in zip(p1, ks))
    c2 = bytes(a ^ b for a, b in zip(p2, ks))
    res = ct.detect_keystream_reuse([c1, c2])
    assert res["verdict"] == "likely keystream reuse"
    assert res["pairs"][0]["identical_prefix"] >= 8   # shared "HEADERv1" header


def test_no_reuse_for_independent_streams():
    c1 = os.urandom(300)
    c2 = os.urandom(300)
    res = ct.detect_keystream_reuse([c1, c2])
    assert res["verdict"] == "no strong reuse signal"


def test_crib_drag_recovers_other_plaintext():
    ks = _ks(120)
    p1 = b"the treasure is buried under the old oak tree near the dock........."
    p2 = b"meet me at midnight by the lighthouse and bring the stolen map too.."
    c1 = bytes(a ^ b for a, b in zip(p1, ks))
    c2 = bytes(a ^ b for a, b in zip(p2, ks))
    hits = ct.crib_drag([c1, c2], b"the treasure is ")
    # crib sits in p1 at offset 0 -> reveals p2's first bytes
    hit0 = [h for h in hits if h["crib_in"] == 0 and h["reveals"] == 1 and h["offset"] == 0]
    assert hit0 and hit0[0]["recovered"] == "meet me at midni"


def test_run_hex_roundtrip():
    # A shared protocol header (as in a real exfil format) makes reuse obvious,
    # and the crib-drag recovers the per-message body regardless.
    ks = _ks(80)
    p1 = b"MSGHDR:: ATTACK AT DAWN, the fleet sails east with the morning tide"
    p2 = b"MSGHDR:: RETREAT AT DUSK, the crew rests west in the sheltered cove"
    c1 = bytes(a ^ b for a, b in zip(p1, ks)).hex()
    c2 = bytes(a ^ b for a, b in zip(p2, ks)).hex()
    out = ct.run([c1, c2], enc="hex", crib="MSGHDR:: ATTACK AT ")
    assert out["verdict"] == "likely keystream reuse"       # shared "MSGHDR:: " prefix
    assert any("RETREAT AT" in h["recovered"] for h in out["crib_hits"])
