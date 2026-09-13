"""Recover an RSA plaintext from the material an encryptor leaves behind.

RSA is the staple of CTF crypto, and the recovery is almost always one of a few
modular exponentiations over values the target already exposes (a modulus N, a
public exponent e, a ciphertext c, and sometimes p/q or d):

* **d given** — decrypt directly: m = c^d mod N.
* **p, q given** — derive d = e^-1 mod (p-1)(q-1), then decrypt.
* **e, c only** — m = c^e mod N. This is signature verification, and it is also
  the recovery when an encryptor **used the private exponent to "encrypt"** (a
  classic bug: computing the modinv in place overwrites the public exponent with
  the private one, so the stored value is m^d and raising it to e returns m —
  no private key needed). Flare-On 'encryptor' is exactly this.
* **factor N** (opt-in) — Fermat factorization when the primes are close
  (a common weak-key generation), giving p/q → d → decrypt.

chimera had no RSA helper at all, so this last step meant hand-rolled Python.
Focused on purpose: modpow with whatever key material is present, plus Fermat.
The exotic single-shot attacks (Wiener low-d, Boneh–Durfee, common-modulus,
Håstad broadcast, factordb lookup) are out of scope — reach for RsaCtfTool.
Pure-Python (uses only `math.isqrt` + 3-arg `pow`); never touches the network.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from math import isqrt

DEFAULT_E = 0x10001


class RsaError(ValueError):
    """Missing/contradictory parameters, or a factorization that did not converge."""


@dataclass
class RsaResult:
    operation: str                         # which path recovered m
    n: int
    e: int
    m: int                                 # recovered plaintext integer
    d: int | None = None                   # private exponent, when known/derived
    p: int | None = None
    q: int | None = None
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        length = (self.n.bit_length() + 7) // 8
        big = self.m.to_bytes(length, "big")
        little = self.m.to_bytes(length, "little")
        out = {
            "operation": self.operation,
            "n_hex": hex(self.n), "e": self.e,
            "m_int": str(self.m), "m_hex": hex(self.m),
            "bytes_big_hex": big.hex(), "bytes_little_hex": little.hex(),
            "printable_big": _printable(big.lstrip(b"\x00")),
            "printable_little": _printable(little.rstrip(b"\x00")),
            "signals": self.signals,
        }
        if self.d is not None:
            out["d_hex"] = hex(self.d)
        if self.p is not None:
            out["p_hex"], out["q_hex"] = hex(self.p), hex(self.q)
        for label, blob in (("text_big", big.lstrip(b"\x00")),
                            ("text_little", little.rstrip(b"\x00"))):
            try:
                out[label] = blob.decode("utf-8")
            except UnicodeDecodeError:
                pass
        return out


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


def parse_int(v: int | str | None, *, base: str = "hex") -> int | None:
    """Parse a value that may be an int, a 0x-hex string, decimal, or base64.

    `base` sets how a bare string (no 0x prefix) is read: "hex" (default — the
    encoding RSA blobs and this challenge's hex lines use), "dec", or "b64".
    """
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v
    s = v.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if base == "dec":
        return int(s, 10)
    if base == "b64":
        return int.from_bytes(base64.b64decode(s, validate=False), "big")
    try:
        return int(s, 16)
    except ValueError as exc:
        raise RsaError(f"could not parse {s!r} as {base}: {exc}") from exc


def fermat_factor(n: int, max_iter: int = 1 << 20) -> tuple[int, int] | None:
    """Factor n = p*q when the primes are close (|p-q| small). None if it does
    not converge within `max_iter` steps."""
    if n <= 0 or n % 2 == 0:
        return (2, n // 2) if n % 2 == 0 and n > 0 else None
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    return None


def rsa_recover(*, n: int, c: int, e: int = DEFAULT_E,
                d: int | None = None, p: int | None = None, q: int | None = None,
                factor: bool = False) -> RsaResult:
    """Recover the plaintext integer via the path the given material supports.

    Priority: explicit d → p,q → (opt-in) factor N → modpow with e. The last
    covers signature verification AND the "encrypted with the private exponent"
    bug where m = c^e mod N with no private key.
    """
    if n <= 0 or c < 0:
        raise RsaError("n must be positive and c non-negative")

    # p,q may be supplied to derive d; or we factor N when asked.
    if d is None and p is None and factor:
        pq = fermat_factor(n)
        if pq is None:
            raise RsaError("Fermat factorization did not converge (primes not close)")
        p, q = pq

    if d is not None:
        return RsaResult("decrypt_d", n, e, pow(c, d, n), d=d,
                         signals=["m = c^d mod N (private exponent supplied)"])

    if p is not None and q is not None:
        if p * q != n:
            raise RsaError("p*q != n")
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError as exc:
            raise RsaError(f"e is not invertible mod phi(N): {exc}") from exc
        return RsaResult("decrypt_pq", n, e, pow(c, d, n), d=d, p=p, q=q,
                         signals=["derived d = e^-1 mod (p-1)(q-1); m = c^d mod N"])

    # Only N, e, c: raise c to e. Recovers m when the encryptor used the private
    # exponent (or verifies a signature).
    return RsaResult("modpow_e", n, e, pow(c, e, n),
                     signals=["m = c^e mod N — plaintext when the encryptor "
                              "'encrypted' with the private exponent, else a "
                              "signature check"])
