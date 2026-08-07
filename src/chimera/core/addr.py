"""Canonical function-address normalization, shared across backends.

Different backends print the same address differently: r2 emits lowercase
`hex(int)` ("0x401000"), Ghidra prints zero-padded hex sometimes carrying an
address-space prefix ("ram:00401000"), the HTTP API accepts whatever the
caller types. Everything that keys on an address — the overlay maps, the
Ghidra→r2 function merge — must agree on one spelling or it silently creates
duplicate entries. `normalize_address` is that single source of truth.
"""

from __future__ import annotations


def normalize_address(addr: str | int) -> str:
    """Canonicalise an address to lowercase ``0x...`` form.

    Accepts an int, a ``0x``-prefixed or bare hex token, or a Ghidra
    ``space:offset`` form (the space prefix is dropped). Falls back to the
    stringified input when it isn't parseable, so a pathological value is
    passed through rather than raising on the hot path.
    """
    if isinstance(addr, int):
        return hex(addr)
    s = str(addr).strip().lower()
    if ":" in s:  # drop Ghidra address-space prefix, e.g. "ram:00401000"
        s = s.rsplit(":", 1)[1]
    # int(s, 16) accepts both "0x401000" and bare "401000".
    try:
        return hex(int(s, 16))
    except ValueError:
        return s
