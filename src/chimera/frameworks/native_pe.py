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

# The compiler embeds panic/location strings referencing the toolchain source
# tree under `/rustc/<40-char commit hash>/library/...`; that path, the cargo
# registry path, and the std source path are the cheapest reliable "this is
# Rust" markers, independent of symbol stripping.
_RUSTC_RE = re.compile(rb"/rustc/[0-9a-f]{16,}")

# Tauri (Rust desktop app: Rust host + a system webview) leaves several reliable
# markers: the JS bridge global `__TAURI_INTERNALS__`/`__TAURI__` injected into the
# webview, the `tauri-<ver>` crates.io dependency path, and the `wry`/`tao`
# (webview/windowing) crates it always pulls in. Tauri is Rust-based, so this is a
# refinement of the plain `rust` tag — it tells the analyst the real logic is a
# Rust `#[tauri::command]` surface behind a webview IPC (`plugin:<name>|<cmd>`),
# and the UI is embedded web assets (see the tauri_extract carver).
_TAURI_VER_RE = re.compile(rb"tauri-(\d+\.\d+\.\d+)")
# A native app that statically links its OWN V8 (rusty_v8) — common in a Tauri app
# that runs game/business logic in an embedded isolate and often runtime-decrypts
# its script (the startup snapshot is usually stock). Worth flagging: the logic may
# not be in the static web assets at all.
_RUSTY_V8_RE = re.compile(rb"rusty_v8-(\d+\.\d+\.\d+)")
_V8_VER_RE = re.compile(rb"\b(\d+\.\d+\.\d+\.\d+)\b")


def _detect_embedded_v8(data: bytes) -> Optional[str]:
    """If the binary statically links rusty_v8, return a short detail string.

    e.g. "embedded V8 via rusty_v8-0.32.1 (V8 9.5.172.19)". Returns None otherwise.
    """
    m = _RUSTY_V8_RE.search(data)
    if not m and b"rusty_v8" not in data:
        return None
    rusty = m.group(1).decode() if m else "?"
    # The V8 version string (x.y.z.w) is emitted near the snapshot/version blob.
    v8 = _V8_VER_RE.search(data)
    v8s = f" (V8 {v8.group(1).decode()})" if v8 else ""
    return f"embedded V8 via rusty_v8-{rusty}{v8s}"


def _detect_tauri(data: bytes) -> Optional[tuple[str, str]]:
    """Recognise a Tauri (Rust + webview) app behind a bare `native`/`rust` label."""
    is_tauri = (
        b"__TAURI_INTERNALS__" in data
        or b"__TAURI__" in data
        or _TAURI_VER_RE.search(data) is not None
        or (b"wry-" in data and b"tao-" in data)
    )
    if not is_tauri:
        return None
    m = _TAURI_VER_RE.search(data)
    ver = f" v{m.group(1).decode()}" if m else ""
    v8 = _detect_embedded_v8(data)
    extra = f"; {v8}" if v8 else ""
    return ("tauri", f"Tauri{ver} (Rust host + webview{extra})")


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


def _detect_rust(data: bytes) -> Optional[tuple[str, str]]:
    """Recognise a Rust binary behind a bare `native` label.

    Rust (rustc/cargo) binaries carry `/rustc/<hash>/library/...` panic-location
    strings, the `cargo/registry` dependency path, and `library/std/src/...`;
    any is a reliable marker and survives stripping (they are in panic metadata,
    not symbols). Tagging it steers the analyst to Rust-aware reversing (heavy
    monomorphised generics, `core::`/`alloc::` noise, often `ring`/`rustls`),
    not C/C++.
    """
    is_rust = (
        _RUSTC_RE.search(data) is not None
        or b"cargo/registry" in data
        or b"cargo\\registry" in data
        or b"library/std/src/" in data
        or b"library/core/src/panicking.rs" in data
        or b"rust_begin_unwind" in data
        or b"rust_eh_personality" in data
    )
    return ("rust", "Rust (rustc/cargo)") if is_rust else None


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

    # Tauri is checked before Rust: it IS Rust, but the more specific tag is more
    # useful (steers to the webview-IPC command surface + embedded web assets).
    tauri = _detect_tauri(data)
    if tauri:
        return tauri

    rust = _detect_rust(data)
    if rust:
        return rust

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
