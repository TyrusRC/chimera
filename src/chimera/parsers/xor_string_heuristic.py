"""Lightweight XOR-key string recovery for ELF binaries.

This is a FLOSS-lite: try every single-byte XOR key against sliding
windows of the binary and surface candidates whose decoded form looks
like ASCII text. Cheap (<2s on a 5MB binary), bounded (max 500
results), and useful for grabbing C2 strings out of unsophisticated
malware.

Runtime is O(255 * len(data) / window_step). For 5 MB at step=8, that
is ~160M comparisons — Python-bound. We accept the trade-off; analysts
who need scale run real FLOSS.
"""
from __future__ import annotations


_PRINTABLE = bytes(range(0x20, 0x7f)) + b"\t\n"
_PRINTABLE_SET = set(_PRINTABLE)


def _printable_run_length(decoded: bytes) -> int:
    """Length of the longest run of printable ASCII bytes."""
    best = current = 0
    for b in decoded:
        if b in _PRINTABLE_SET:
            current += 1
            if current > best:
                best = current
        else:
            current = 0
    return best


def find_xor_strings(
    data: bytes,
    *,
    window: int = 32,
    step: int = 8,
    min_run: int = 6,
    min_printable_pct: float = 0.7,
    max_results: int = 500,
) -> list[dict]:
    """Find XOR-encoded ASCII strings in `data`.

    Returns: [{"address": int, "key": int, "value": str}, ...].
    `address` is the offset within `data` where the candidate begins.
    """
    if not data:
        return []
    out: list[dict] = []
    n = len(data)
    pct_threshold = window * min_printable_pct
    for offset in range(0, n - window + 1, step):
        chunk = data[offset:offset + window]
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in chunk)
            printable_count = sum(1 for b in decoded if b in _PRINTABLE_SET)
            if printable_count < pct_threshold:
                continue
            if _printable_run_length(decoded) < min_run:
                continue
            # Trim to the printable prefix for the value
            tail = 0
            while tail < len(decoded) and decoded[tail] in _PRINTABLE_SET:
                tail += 1
            value = decoded[:tail].decode("ascii", errors="replace")
            out.append({
                "address": offset,
                "key": key,
                "value": value,
            })
            if len(out) >= max_results:
                return out
            break  # don't try other keys at this offset
    return out
