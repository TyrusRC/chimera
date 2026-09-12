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

import re
from typing import Iterable, Optional

# The .go.buildinfo blob every gc-compiled Go 1.13+ binary embeds starts with
# this 14-byte magic; it is the single most reliable "this is Go" marker and is
# independent of whether symbols were stripped.
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?")

_DOTNET_CORE_RE = re.compile(rb"\.NETCoreApp,Version=v(\d+\.\d+)")


def _present(data: bytes, needle: bytes) -> bool:
    """True if `needle` appears as ASCII or UTF-16LE (VB stores both)."""
    return needle in data or needle.decode("ascii").encode("utf-16-le") in data


def _detect_go(data: bytes) -> Optional[tuple[str, str]]:
    """Recognise a gc-compiled Go binary and, if possible, name the version.

    Checked before the VB6 family because these markers are unambiguous: the
    go.buildinfo magic, the `Go build ID` note, or the `go1.x` runtime version
    string. r2 already symbolises Go via the pclntab, so tagging the framework
    is the missing half — an analyst who sees `native` chases C/C++.
    """
    is_go = (
        _GO_BUILDINFO_MAGIC in data
        or b"Go build ID: \"" in data
        or b"runtime.goexit" in data
    )
    if not is_go:
        return None
    m = _GO_VERSION_RE.search(data)
    return ("go", f"Go ({m.group(0).decode()})" if m else "Go (gc toolchain)")


def _detect_dotnet_aot(data: bytes) -> Optional[tuple[str, str]]:
    """Recognise a .NET NativeAOT binary — a native PE, not IL.

    NativeAOT emits two section names unique to it: `.managed` (managed
    metadata/type system) and `hydrated` (the run-time-rehydrated data blob).
    Both present is an unambiguous signature; the `.NETCoreApp,Version=vX.Y`
    string, when present, names the version. Tagging it tells the analyst this
    is .NET compiled to native code (no IL to decompile — treat as native RE,
    and expect a managed crypto stack like BouncyCastle), not plain C/C++.
    """
    if b".managed" not in data or b"hydrated" not in data:
        return None
    m = _DOTNET_CORE_RE.search(data)
    ver = f" v{m.group(1).decode()}" if m else ""
    return ("dotnet-aot", f".NET NativeAOT{ver} (native, no IL)")


def detect_native_runtime(
    data: bytes, import_dlls: Iterable[str]
) -> Optional[tuple[str, str]]:
    dlls = {d.lower() for d in import_dlls if d}

    go = _detect_go(data)
    if go:
        return go

    aot = _detect_dotnet_aot(data)
    if aot:
        return aot

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
