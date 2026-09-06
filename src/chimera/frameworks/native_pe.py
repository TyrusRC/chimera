"""Fingerprint the language/runtime behind a *native* PE.

`analyze` otherwise labels every non-.NET, non-PyInstaller PE simply
`native`, which reads as "C/C++" and sends an analyst down the wrong path.
Several native runtimes leave a cheap, reliable fingerprint — this recovers
the most common one that hides behind `native`: the VB6-compatible family
(classic Visual Basic 6 and the modern twinBASIC compiler, which bakes the
same `ThunderRT6*` runtime window classes in natively).

Returns `(framework_value, detail)` where `framework_value` matches a
`Framework` enum value, or None when nothing recognisable is present.
"""
from __future__ import annotations

from typing import Iterable, Optional


def _present(data: bytes, needle: bytes) -> bool:
    """True if `needle` appears as ASCII or UTF-16LE (VB stores both)."""
    return needle in data or needle.decode("ascii").encode("utf-16-le") in data


def detect_native_runtime(
    data: bytes, import_dlls: Iterable[str]
) -> Optional[tuple[str, str]]:
    dlls = {d.lower() for d in import_dlls if d}

    # twinBASIC self-identifies in its runtime error strings.
    if _present(data, b"twinBASIC"):
        return ("vb6", "twinBASIC")

    # Classic VB6 links the p-code/native runtime by import.
    if "msvbvm60.dll" in dlls:
        return ("vb6", "classic VB6 / MSVBVM60")

    # Both classic VB6 and twinBASIC register the ThunderRT6* window classes.
    if _present(data, b"ThunderRT6"):
        return ("vb6", "VB6-compatible / ThunderRT6")

    return None
