"""Fingerprint the language/runtime behind a *native* Mach-O.

The Mach-O pipeline otherwise labels every binary `native`, which reads as
"C/C++". Some runtimes leave a cheap, reliable fingerprint — this recovers
Crystal-lang, which compiles to a native Mach-O (or ELF) that an analyst would
otherwise chase as C/C++. A Crystal binary carries its runtime type/fiber names
(`Fiber::ExecutionContext*`, `Crystal::*`) and the `__crystal_main` entry even
when stripped of user symbols, and even when the stdlib strings are obfuscated
(FLARE-On 13 ch3 leet-encoded them — the class-name table survives).

Returns `(framework_value, detail)` matching a `Framework` enum value, or None.
"""
from __future__ import annotations

import re
from typing import Optional

_CRYSTAL_VERSION_RE = re.compile(rb"Crystal (\d+\.\d+\.\d+)")


def _detect_crystal(data: bytes) -> Optional[tuple[str, str]]:
    """Recognise a Crystal-lang native binary.

    `Fiber::ExecutionContext` is the distinctive marker (Crystal's fiber
    scheduler type, present across the runtime); `__crystal_main` is the
    compiled top-level entry. Either is enough — both survive stripping and the
    leet string-obfuscation seen in the wild.
    """
    is_crystal = (
        b"Fiber::ExecutionContext" in data
        or b"__crystal_main" in data
        or b"crystal_main" in data
        or b"Crystal::System" in data
    )
    if not is_crystal:
        return None
    m = _CRYSTAL_VERSION_RE.search(data)
    return ("crystal", f"Crystal ({m.group(1).decode()})" if m else "Crystal-lang")


def detect_macho_runtime(data: bytes) -> Optional[tuple[str, str]]:
    """Dispatch native Mach-O runtime detection (mirrors native_pe)."""
    crystal = _detect_crystal(data)
    if crystal:
        return crystal
    return None
