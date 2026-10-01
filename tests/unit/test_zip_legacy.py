"""Tests for legacy PKZIP ZipCrypto + Reduce (unpacking/zip_legacy.py)."""
from __future__ import annotations

from chimera.unpacking.zip_legacy import (
    _crc32_byte, reduce_decompress, zipcrypto_decrypt,
)


def _zipcrypto_encrypt(plaintext: bytes, password: bytes, header: bytes) -> bytes:
    """Inverse of zipcrypto_decrypt (for round-trip testing). Prepends a 12-byte header."""
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def update(c):
        nonlocal k0, k1, k2
        k0 = _crc32_byte(k0, c)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)

    for c in password:
        update(c)
    out = bytearray()
    for p in header + plaintext:
        temp = (k2 | 2) & 0xFFFF
        out.append(p ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
        update(p)
    return bytes(out)


def test_zipcrypto_roundtrip():
    pt = b"the crow flies at midnight, arr"
    ct = _zipcrypto_encrypt(pt, b"infected", header=b"0123456789AB")
    assert zipcrypto_decrypt(ct, b"infected") == pt


def test_reduce_backreference_lz_path():
    # 192 bytes of zero = 256 empty follower sets (6 bits each). Then literals
    # 'A','B', a DLE match (V=0x01 → len field 1, dist byte 1 → dist 2, len 4)
    # copies back → "ABABAB".
    data = bytes(192) + bytes([0x41, 0x42, 0x90, 0x01, 0x01])
    assert reduce_decompress(data, factor=1, out_size=6) == b"ABABAB"


def test_reduce_real_ch3_vector():
    # The actual FLARE-On 13 ch3 flag.txt, post-ZipCrypto (pw "infected"),
    # method-2 Reduce (factor 1), usize 18 → "reduce_not_deflate".
    hexv = ("00" * 192) + "7265647563655f6e6f745f6465666c617465"
    data = bytes.fromhex(hexv)
    assert reduce_decompress(data, factor=1, out_size=18) == b"reduce_not_deflate"
