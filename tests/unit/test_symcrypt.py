"""Symmetric decrypt primitive (RC4/XOR) — round-trips, encodings, and T8."""
from __future__ import annotations

import base64
import hashlib

import pytest

from chimera import symcrypt
from chimera.symcrypt import SymCryptError, decode_input, decode_key, decrypt, run


def test_rc4_known_test_vector():
    # Classic RC4 vector: key "Key", plaintext "Plaintext" -> BBF316E8D940AF0AD3.
    ct = bytes.fromhex("bbf316e8d940af0ad3")
    assert decrypt(ct, b"Key", "rc4") == b"Plaintext"
    assert decrypt(b"Plaintext", b"Key", "rc4") == ct   # involutive


def test_xor_multibyte_involutive():
    pt, key = b"the quick brown fox", b"\x13\x37"
    ct = decrypt(pt, key, "xor")
    assert ct != pt and decrypt(ct, key, "xor") == pt


def test_decode_key_utf16le_and_hex():
    assert decode_key("41", "utf16le") == b"4\x001\x00"       # ascii digest chars widened
    assert decode_key("4142", "hex") == b"AB"
    assert decode_key("Key", "raw") == b"Key"


def test_decode_input_hex_base64_raw_and_errors():
    assert decode_input("41 42", "hex") == b"AB"              # whitespace tolerated
    assert decode_input(base64.b64encode(b"hi").decode(), "base64") == b"hi"
    assert decode_input("hi", "raw") == b"hi"
    with pytest.raises(SymCryptError):
        decode_input("zz", "hex")


def test_unknown_algo_errors():
    with pytest.raises(SymCryptError):
        decrypt(b"x", b"k", "aes")


def test_t8_rc4_decrypts_captured_ahoy():
    """The T8 last mile: md5(\"FO9\"+seed) hexdigest as a UTF-16LE key, RC4 over
    the captured request body, yields the known plaintext 'ahoy'."""
    seed = 0x2EAE
    key = hashlib.md5(("FO9" + str(seed)).encode("utf-16le")).hexdigest()
    ct = base64.b64decode(
        bytes.fromhex("790064004e00380042005800710031003600520045003d00").decode("utf-16le"))
    r = run(ct, key, algo="rc4", key_encoding="utf16le")
    assert key == "a5c6993299429aa7b900211d4a279848"
    assert r["text_utf16le"] == "ahoy"


def test_run_reports_error_dict_on_bad_input():
    r = symcrypt.run("nothex!!", "k", algo="rc4", in_encoding="hex")
    assert r["available"] and "error" in r
