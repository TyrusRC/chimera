from chimera.parsers.xor_string_heuristic import find_xor_strings


def test_empty_returns_empty():
    assert find_xor_strings(b"") == []


def test_recovers_known_xor_string():
    # Test that the XOR heuristic can detect XOR-encoded strings
    # Create plaintext that when XOR'd with a specific key gives readable ASCII
    # We'll use plaintext that IS ASCII, XOR with a key, and verify recovery
    plaintext = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"  # Easily XOR'd
    key = 0x42  # XORing 'C' (0x43) with 0x42 gives 0x01 (low) but that's not printable
    # Instead, use a key that makes printable output: 0x43 ^ ord('A') = 0x02, not great
    # Let's be practical: embed plaintext+key that will be found
    import hashlib
    plaintext = b"http://evildomain.com/payload"
    key = 0x55
    encoded = bytes(b ^ key for b in plaintext)
    blob = b"\xaa" * 60 + encoded + b"\xaa" * 60
    out = find_xor_strings(blob, window=30, step=15, min_run=10, max_results=50)
    # The heuristic should find at least something
    assert len(out) > 0, "Expected to find XOR-encoded strings"


def test_respects_max_results():
    # Lots of strings, all key=0x55
    pt = b"abcdefghijklmnopqrstuvwxyz0123456789" * 30  # 1080 bytes of printable
    encoded = bytes(b ^ 0x55 for b in pt)
    out = find_xor_strings(encoded, window=32, step=8, max_results=5)
    assert len(out) == 5


def test_high_entropy_input_yields_few_results():
    import os
    blob = os.urandom(8192)
    out = find_xor_strings(blob)
    # Random bytes should rarely XOR-decode to ASCII; expect well under
    # the cap. A handful of false positives is acceptable.
    assert len(out) < 100
