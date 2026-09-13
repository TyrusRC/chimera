"""RSA plaintext recovery — modpow paths + Fermat (ch9 encryptor)."""
from __future__ import annotations

import pytest

from Crypto.Util.number import getPrime, isPrime

from chimera.rsatool import RsaError, fermat_factor, parse_int, rsa_recover
from chimera.symcrypt import decrypt

# A real RSA instance with CLOSE primes (so Fermat converges), small enough to
# be fast. q is the next prime above p → |p-q| tiny.
_P = getPrime(128)
_Q = _P + 2
while not isPrime(_Q):
    _Q += 2
_N = _P * _Q
_E = 0x10001
_D = pow(_E, -1, (_P - 1) * (_Q - 1))


def test_decrypt_with_d():
    m = 0x4242
    c = pow(m, _E, _N)                        # normal encrypt
    r = rsa_recover(n=_N, c=c, e=_E, d=_D)
    assert r.operation == "decrypt_d" and r.m == m


def test_decrypt_with_pq_derives_d():
    m = 0x1337
    c = pow(m, _E, _N)
    r = rsa_recover(n=_N, c=c, e=_E, p=_P, q=_Q)
    assert r.operation == "decrypt_pq" and r.m == m and r.d == _D


def test_modpow_e_recovers_private_exponent_encryption():
    """The ch9 bug: the file's value is m^d (encryptor used the PRIVATE
    exponent), so raising it to e returns m — no private key needed."""
    m = 0xC0FFEE
    stored = pow(m, _D, _N)                    # "encrypted" with d
    r = rsa_recover(n=_N, c=stored, e=_E)      # only N, e, c
    assert r.operation == "modpow_e" and r.m == m


def test_factor_flag_recovers_close_primes():
    m = 0x99
    c = pow(m, _E, _N)                         # p,q are close → Fermat converges
    r = rsa_recover(n=_N, c=c, e=_E, factor=True)
    assert r.m == m and {r.p, r.q} == {_P, _Q}


def test_fermat_gives_up_on_far_primes():
    n = 3 * (2 ** 61 - 1)                       # wildly unbalanced factors
    assert fermat_factor(n, max_iter=1000) is None


def test_pq_mismatch_errors():
    with pytest.raises(RsaError):
        rsa_recover(n=_N + 1, c=1, e=_E, p=_P, q=_Q)


def test_parse_int_bases():
    assert parse_int("0x10001") == 0x10001
    assert parse_int("10001", base="hex") == 0x10001
    assert parse_int("65537", base="dec") == 65537
    assert parse_int(None) is None


def test_ch9_end_to_end_rsa_then_chacha20():
    """Full ch9 last mile: RSA-recover the little-endian ChaCha20 key from the
    'encrypted' key value, then ChaCha20-decrypt the body. Uses a real 1024-bit
    modulus so the 256-bit key fits (n > key)."""
    from Crypto.Util.number import getPrime

    p, q = getPrime(512), getPrime(512)
    n = p * q
    d = pow(_E, -1, (p - 1) * (q - 1))
    length = (n.bit_length() + 7) // 8

    key = bytes.fromhex("01b097a12a39fc420524a2e775a743c928d5a550b1879aa8b415571e38329b98")
    nonce = bytes.fromhex("0249fc0fc83340fe4d928f95")
    flag = b"R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com"
    body_ct = decrypt(flag, key, "chacha20", nonce=nonce)

    # The encryptor stores stored_key = key^d mod N (key as a little-endian int).
    key_int = int.from_bytes(key, "little")
    stored_key = pow(key_int, d, n)

    r = rsa_recover(n=n, c=stored_key, e=_E)           # recover with e only
    recovered = r.m.to_bytes(length, "little")[:32]
    assert recovered == key
    assert decrypt(body_ct, recovered, "chacha20", nonce=nonce) == flag
