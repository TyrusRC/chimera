"""Symmetric decrypt for a captured / embedded blob — RC4 and XOR, key supplied.

chimera could FIND an AES key (`aes_keyfind`) and had an RC4 buried inside the PDF
decryptor, but had no general "decrypt this captured blob with a known key"
primitive — the exact last step of a network-capture RE challenge once the key is
recovered, and RC4 / XOR are among the most common malware + CTF ciphers. This
wraps the vetted RC4 (reused from `unpacking.pdfcrypt`) and single/multi-byte XOR
with flexible decoding on both sides:

* input encoding — raw / hex / base64 (traffic is usually base64 or hex),
* key encoding — raw / hex / **utf16le** (a key that is a hex-DIGEST string
  encoded as UTF-16LE, e.g. Flare-On "T8": `md5("FO9"+seed).hexdigest()` taken as
  UTF-16LE bytes).

Recovering the key itself (a brute-forced RNG seed, a KDF) is target-specific and
left to the analyst; this is the reusable cipher step.
"""
from __future__ import annotations

import base64
import binascii

from chimera.unpacking.pdfcrypt import rc4 as _rc4

ALGOS = ("rc4", "xor", "chacha20", "salsa20")
_STREAM_ALGOS = ("chacha20", "salsa20")   # need a nonce (+ optional counter)
_INPUT_ENCODINGS = ("raw", "hex", "base64")
_KEY_ENCODINGS = ("raw", "hex", "utf16le")


class SymCryptError(ValueError):
    """Bad algorithm, encoding, or undecodable input/key."""


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise SymCryptError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _chacha_salsa(data: bytes, key: bytes, nonce: bytes, counter: int, algo: str) -> bytes:
    """ChaCha20 / Salsa20 keystream XOR (involutive). Backed by pycryptodome.

    ChaCha20 takes an 8- or 12-byte nonce (12 = RFC 7539, 32-bit block counter);
    Salsa20 takes an 8-byte nonce. `counter` is the initial block counter (the
    `in[12]` word in a hand-rolled ChaCha state) — applied via a keystream seek.
    """
    try:
        if algo == "chacha20":
            from Crypto.Cipher import ChaCha20 as _C
        else:
            from Crypto.Cipher import Salsa20 as _C
    except ImportError as exc:  # pycryptodome is a hard dep, but fail loud if missing
        raise SymCryptError(f"{algo} needs pycryptodome: {exc}") from exc
    if len(key) not in (16, 32):
        raise SymCryptError(f"{algo} key must be 16 or 32 bytes, got {len(key)}")
    try:
        cipher = _C.new(key=key, nonce=nonce)
    except ValueError as exc:
        raise SymCryptError(f"{algo} nonce invalid: {exc}") from exc
    if counter:
        if algo != "chacha20":
            raise SymCryptError("counter is only supported for chacha20")
        cipher.seek(counter * 64)   # skip `counter` 64-byte keystream blocks
    return cipher.decrypt(data)


def decrypt(data: bytes, key: bytes, algo: str = "rc4", *,
            nonce: bytes = b"", counter: int = 0) -> bytes:
    """Apply `algo` — all supported ciphers are involutive, so decrypt == encrypt.

    rc4 / xor ignore `nonce`/`counter`; chacha20 / salsa20 require a `nonce`.
    """
    if algo == "rc4":
        if not key:
            raise SymCryptError("empty RC4 key")
        return _rc4(key, data)
    if algo == "xor":
        return _xor(data, key)
    if algo in _STREAM_ALGOS:
        return _chacha_salsa(data, key, nonce, counter, algo)
    raise SymCryptError(f"unknown algo {algo!r}; supported: {', '.join(ALGOS)}")


def decode_input(s: str | bytes, encoding: str) -> bytes:
    """Decode ciphertext text into bytes per `encoding` (raw/hex/base64)."""
    if encoding == "raw":
        return s if isinstance(s, bytes) else s.encode("utf-8", "surrogateescape")
    text = (s.decode("latin-1") if isinstance(s, bytes) else s).strip()
    try:
        if encoding == "hex":
            return bytes.fromhex(text)
        if encoding == "base64":
            return base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise SymCryptError(f"could not {encoding}-decode input: {exc}") from exc
    raise SymCryptError(f"unknown input encoding {encoding!r}; supported: {', '.join(_INPUT_ENCODINGS)}")


def decode_key(s: str | bytes, encoding: str) -> bytes:
    """Decode a key per `encoding` — raw / hex / utf16le (a hex-digest string as UTF-16LE)."""
    if isinstance(s, bytes):
        return s
    if encoding == "raw":
        return s.encode("utf-8", "surrogateescape")
    if encoding == "utf16le":
        return s.encode("utf-16le")
    if encoding == "hex":
        try:
            return bytes.fromhex(s.strip())
        except ValueError as exc:
            raise SymCryptError(f"could not hex-decode key: {exc}") from exc
    raise SymCryptError(f"unknown key encoding {encoding!r}; supported: {', '.join(_KEY_ENCODINGS)}")


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


def run(data: str | bytes, key: str | bytes, *, algo: str = "rc4",
        in_encoding: str = "raw", key_encoding: str = "raw",
        nonce: str | bytes = b"", nonce_encoding: str = "hex",
        counter: int = 0) -> dict:
    """Decode + decrypt, returning the bytes plus readable previews.

    Also surfaces a UTF-16LE decode of the plaintext, since Windows malware
    (and T8) frequently keeps the plaintext as wide chars. `nonce`/`counter`
    apply to the stream ciphers (chacha20/salsa20); the nonce decodes with the
    same raw/hex/base64 scheme as the ciphertext.
    """
    try:
        raw = decode_input(data, in_encoding)
        k = decode_key(key, key_encoding)
        n = decode_input(nonce, nonce_encoding) if nonce else b""
        out = decrypt(raw, k, algo, nonce=n, counter=counter)
    except SymCryptError as exc:
        return {"available": True, "error": str(exc)}

    result = {
        "available": True, "algo": algo, "byte_count": len(out),
        "hex": out.hex(), "printable": _printable(out),
        "key_len": len(k),
    }
    # Best-effort text views — included only when they decode cleanly.
    try:
        result["text_utf8"] = out.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        if len(out) % 2 == 0:
            t16 = out.decode("utf-16le")
            if all(c == "\t" or c == "\n" or 0x20 <= ord(c) < 0xFFFD for c in t16):
                result["text_utf16le"] = t16
    except UnicodeDecodeError:
        pass
    return result
