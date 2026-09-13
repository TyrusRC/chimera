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


# --- ChaCha20 / Salsa20 (ch9 encryptor) --------------------------------------

def test_chacha20_rfc8439_test_vector():
    """RFC 8439 §2.4.2: key = 00..1f, nonce = 00 00 00 00 00 00 00 4a 00 00 00 00,
    counter = 1, over the known 'Ladies and Gentlemen…' plaintext."""
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                 b"only one tip for the future, sunscreen would be it.")
    ct = decrypt(plaintext, key, "chacha20", nonce=nonce, counter=1)
    assert ct[:8].hex() == "6e2e359a2568f980"        # RFC 8439 keystream start
    # Involutive: decrypting the ciphertext returns the plaintext.
    assert decrypt(ct, key, "chacha20", nonce=nonce, counter=1) == plaintext


def test_chacha20_recovers_flag_after_rsa_key(tmp_path):
    """The ch9 last mile: given the RSA-recovered 32-byte key + 12-byte nonce,
    ChaCha20 decrypts the file body. Round-trip with a known key/nonce."""
    key = bytes.fromhex("01b097a12a39fc420524a2e775a743c928d5a550b1879aa8b415571e38329b98")
    nonce = bytes.fromhex("0249fc0fc83340fe4d928f95")
    flag = b"R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com"
    ct = decrypt(flag, key, "chacha20", nonce=nonce)     # counter defaults to 0
    assert decrypt(ct, key, "chacha20", nonce=nonce) == flag


def test_chacha20_via_run_with_hex_nonce():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    ct = decrypt(b"hello world", key, "chacha20", nonce=nonce, counter=1)
    r = run(ct.hex(), key.hex(), algo="chacha20", in_encoding="hex",
            key_encoding="hex", nonce=nonce.hex(), nonce_encoding="hex", counter=1)
    assert r["text_utf8"] == "hello world"


def test_salsa20_round_trip():
    key = bytes(range(32))
    nonce = bytes.fromhex("0011223344556677")   # salsa20 nonce = 8 bytes
    ct = decrypt(b"secret bytes", key, "salsa20", nonce=nonce)
    assert decrypt(ct, key, "salsa20", nonce=nonce) == b"secret bytes"


def test_chacha20_bad_key_length_errors():
    with pytest.raises(SymCryptError):
        decrypt(b"x", b"shortkey", "chacha20", nonce=bytes(12))


def test_counter_rejected_for_salsa20():
    with pytest.raises(SymCryptError):
        decrypt(b"x", bytes(32), "salsa20", nonce=bytes(8), counter=1)
