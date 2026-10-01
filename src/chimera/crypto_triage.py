"""Crypto triage: detect keystream REUSE across several ciphertexts (the
multi-time-pad weakness) and crib-drag to recover plaintext.

A stream cipher (RC4, ChaCha/AES-CTR, a hand-rolled XOR keystream) is broken the
moment the same key+nonce encrypts two messages: C_i ⊕ C_j = P_i ⊕ P_j, leaking
the plaintexts with no key. FLARE-On 13 ch5 "catthief" re-keyed RC4 from scratch
per message, so all exfil bodies shared one keystream — visible as identical
ciphertext prefixes. chimera had decrypt_blob (apply a known key) but nothing to
SPOT reuse or exploit it. This scores the reuse signal across a set of blobs and
drags a known crib to recover keystream (and hence every plaintext) at matched
positions. Read-only, no key needed.
"""
from __future__ import annotations

import base64
import binascii
from pathlib import Path


class CryptoTriageError(Exception):
    pass


def _decode_one(s: str, enc: str) -> bytes:
    if enc == "file":
        return Path(s).read_bytes()
    if enc == "hex":
        return binascii.unhexlify(s.strip().replace(" ", ""))
    if enc == "base64":
        return base64.b64decode(s)
    if enc == "raw":
        return s.encode("latin-1")
    raise CryptoTriageError(f"unknown enc {enc!r} (use hex/base64/file/raw)")


def _printable(b: int) -> bool:
    return 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)


def detect_keystream_reuse(cts: list[bytes]) -> dict:
    """Score whether `cts` share a keystream. Returns pairwise stats + verdict.

    Signals (all survive high-entropy plaintexts to some degree):
    - identical-prefix length (same keystream + same plaintext header → equal bytes),
    - zero-XOR fraction (equal plaintext bytes at a position),
    - printable-XOR fraction (P_i⊕P_j is printable far more often for text than
      for two independent random streams, where it's ~31%).
    """
    pairs = []
    reuse_votes = 0
    n = len(cts)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = cts[i], cts[j]
            m = min(len(a), len(b))
            if m == 0:
                continue
            x = bytes(p ^ q for p, q in zip(a, b))
            # identical prefix
            pref = 0
            while pref < m and x[pref] == 0:
                pref += 1
            zero = sum(1 for c in x if c == 0)
            pr = sum(1 for c in x if _printable(c))
            # longest zero run
            best = cur = 0
            for c in x:
                cur = cur + 1 if c == 0 else 0
                best = max(best, cur)
            printable_frac = pr / m
            vote = pref >= 4 or best >= 8 or printable_frac >= 0.50
            reuse_votes += 1 if vote else 0
            pairs.append({"i": i, "j": j, "overlap": m,
                          "identical_prefix": pref, "longest_zero_run": best,
                          "zero_frac": round(zero / m, 4),
                          "printable_xor_frac": round(printable_frac, 4),
                          "reuse_signal": vote})
    total = max(1, len(pairs))
    verdict = ("likely keystream reuse" if reuse_votes >= total / 2
               else "no strong reuse signal")
    return {"available": True, "n_ciphertexts": n, "pairs": pairs,
            "reuse_pairs": reuse_votes, "verdict": verdict,
            "note": ("random-independent streams XOR to ~31% printable and share "
                     "no prefix; a high printable-XOR / shared prefix ⇒ reuse")}


def crib_drag(cts: list[bytes], crib: bytes) -> list[dict]:
    """Slide `crib` (a guessed plaintext fragment) over each pairwise XOR.

    At a position where crib == P_i, (C_i⊕C_j)⊕crib == P_j, so a hit is a window
    where the recovered P_j is all-printable across the other ciphertexts. Returns
    candidate positions with the recovered text (the classic two-time-pad attack).
    """
    hits = []
    n = len(cts)
    L = len(crib)
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            a, b = cts[i], cts[j]
            m = min(len(a), len(b))
            x = bytes(p ^ q for p, q in zip(a, b))
            for off in range(0, m - L + 1):
                rec = bytes(x[off + k] ^ crib[k] for k in range(L))
                if all(_printable(c) for c in rec):
                    hits.append({"crib_in": i, "reveals": j, "offset": off,
                                 "recovered": rec.decode("latin-1")})
    # de-dupe / rank by offset
    hits.sort(key=lambda h: (h["offset"], h["reveals"]))
    return hits


def run(inputs: list[str], *, enc: str = "hex", crib: str | None = None) -> dict:
    """Decode `inputs` and run reuse detection (+ optional crib-drag)."""
    if not inputs or len(inputs) < 2:
        return {"available": True, "error": "need at least 2 ciphertexts"}
    try:
        cts = [_decode_one(s, enc) for s in inputs]
    except (CryptoTriageError, binascii.Error, ValueError, OSError) as exc:
        return {"available": True, "error": f"decode failed: {exc}"}
    out = detect_keystream_reuse(cts)
    if crib:
        cb = crib.encode("latin-1")
        out["crib"] = crib
        out["crib_hits"] = crib_drag(cts, cb)[:50]
    return out
