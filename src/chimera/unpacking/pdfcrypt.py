"""PDF Standard security handler — derive the key and decrypt, statically.

Covers the ISO 32000 Standard handler revisions 2-6: RC4 (R2-R4), AESV2
(R4) and AESV3 (R5/R6, AES-256). The modern case (V5/R6, AESV3) uses the
hardened Algorithm 2.B hash and the file key directly; the legacy case
(V<=4) uses the MD5-based Algorithm 2 with a per-object key.

Crypto primitives: RC4 is implemented here (tiny, keeps the core dep-free);
AES comes from :mod:`Crypto` (pycryptodome), the optional ``[pdf]`` extra.
Without it, recon and trap detection still work and decryption reports that
the extra is missing rather than crashing.

The MD5 in the legacy key derivation is the PDF *format* algorithm, not a
security choice — it is called with ``usedforsecurity=False`` to say so.
"""
from __future__ import annotations

import hashlib
import struct

# Fixed 32-byte password padding string (ISO 32000-1, Algorithm 2, step a).
_PAD = bytes([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
])


class PdfCryptError(RuntimeError):
    """Raised when decryption cannot proceed (e.g. AES support absent)."""


def _aes():
    """Import pycryptodome's AES lazily with a clear install hint."""
    try:
        from Crypto.Cipher import AES  # noqa: PLC0415
        return AES
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise PdfCryptError(
            "AES support requires pycryptodome — install with: pip install 'chimera[pdf]'"
        ) from e


def rc4(key: bytes, data: bytes) -> bytes:
    """Plain RC4 keystream XOR (used by the legacy RC4 handlers)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = c ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def hash_r6(password: bytes, salt: bytes, udata: bytes = b"") -> bytes:
    """ISO 32000-2 Algorithm 2.B — the hardened R6 hash.

    `udata` is empty for a user password and the 48-byte `/U` for an owner
    password. Returns a 32-byte digest.
    """
    AES = _aes()
    K = hashlib.sha256(password + salt + udata).digest()
    i = 0
    while True:
        K1 = (password + K + udata) * 64
        E = AES.new(K[:16], AES.MODE_CBC, K[16:32]).encrypt(K1)
        mod = sum(E[:16]) % 3
        if mod == 0:
            K = hashlib.sha256(E).digest()
        elif mod == 1:
            K = hashlib.sha384(E).digest()
        else:
            K = hashlib.sha512(E).digest()
        i += 1
        # Round count is open-ended; stop once we've done >=64 rounds and the
        # last byte of E no longer exceeds round-32 (spec step f).
        if i >= 64 and E[-1] <= i - 32:
            break
    return K[:32]


def derive_file_key_r6(password: bytes, U: bytes, UE: bytes) -> bytes | None:
    """R5/R6 user-password path: validate against `/U`, return the file key or None.

    `/U` = 32-byte hash || 8-byte validation salt || 8-byte key salt. The file
    key is `AES-256-CBC(no-IV, key=Hash(password + key_salt))`-decrypt of `/UE`.
    """
    if len(U) < 48 or len(UE) < 32:
        return None
    if hash_r6(password, U[32:40]) != U[:32]:
        return None
    intermediate = hash_r6(password, U[40:48])
    AES = _aes()
    return AES.new(intermediate, AES.MODE_CBC, b"\x00" * 16).decrypt(UE[:32])


def aesv3_decrypt(file_key: bytes, blob: bytes) -> bytes:
    """Decrypt an AESV3 stream/string: 16-byte IV prefix + AES-256-CBC, unpadded."""
    AES = _aes()
    if len(blob) < 16:
        return b""
    iv, ct = blob[:16], blob[16:]
    if len(ct) % 16:
        ct = ct[: len(ct) - (len(ct) % 16)]
    pt = AES.new(file_key, AES.MODE_CBC, iv).decrypt(ct)
    return _strip_pkcs7(pt)


def _strip_pkcs7(pt: bytes) -> bytes:
    if not pt:
        return pt
    n = pt[-1]
    if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
        return pt[:-n]
    return pt


def _md5(*chunks: bytes) -> bytes:
    m = hashlib.md5(usedforsecurity=False)  # PDF format algorithm, not security
    for c in chunks:
        m.update(c)
    return m.digest()


class SecurityHandler:
    """A parsed Standard security handler ready to derive a key and decrypt.

    Construct from the fields of the `/Encrypt` dict plus the first `/ID`
    element. `file_key(password)` returns the key or None (wrong password);
    once a key is held, `decrypt(num, gen, data)` decrypts one object.
    """

    def __init__(self, *, V: int, R: int, length: int, P: int,
                 O: bytes, U: bytes, UE: bytes = b"", OE: bytes = b"",
                 id0: bytes = b"", encrypt_metadata: bool = True,
                 cfm: str = "V2"):
        self.V = V
        self.R = R
        self.length = length or (40 if R < 3 else 128)  # bits
        self.P = P
        self.O, self.U, self.UE, self.OE = O, U, UE, OE
        self.id0 = id0
        self.encrypt_metadata = encrypt_metadata
        self.cfm = cfm  # 'V2' (RC4), 'AESV2', or 'AESV3'
        self._key: bytes | None = None

    @property
    def is_aesv3(self) -> bool:
        return self.V >= 5 or self.cfm == "AESV3"

    def file_key(self, password: bytes = b"") -> bytes | None:
        if self.is_aesv3:
            self._key = derive_file_key_r6(password, self.U, self.UE)
        else:
            self._key = self._legacy_key(password)
        return self._key

    def _legacy_key(self, password: bytes) -> bytes:
        n = self.length // 8
        pw = (password + _PAD)[:32]
        parts = [pw, self.O[:32], struct.pack("<i", self.P), self.id0]
        if self.R >= 4 and not self.encrypt_metadata:
            parts.append(b"\xff\xff\xff\xff")
        key = _md5(*parts)
        if self.R >= 3:
            for _ in range(50):
                key = _md5(key[:n])
        return key[:n]

    def decrypt(self, num: int, gen: int, data: bytes) -> bytes:
        if self._key is None:
            raise PdfCryptError("no file key derived — call file_key() first")
        if self.is_aesv3:
            return aesv3_decrypt(self._key, data)
        # Legacy per-object key (Algorithm 1).
        salt = b"sAlT" if self.cfm == "AESV2" else b""
        ok = _md5(self._key, struct.pack("<I", num)[:3],
                  struct.pack("<I", gen)[:2], salt)
        ok = ok[: min(len(self._key) + 5, 16)]
        if self.cfm == "AESV2":
            AES = _aes()
            if len(data) < 16:
                return b""
            return _strip_pkcs7(
                AES.new(ok, AES.MODE_CBC, data[:16]).decrypt(data[16:])
            )
        return rc4(ok, data)
