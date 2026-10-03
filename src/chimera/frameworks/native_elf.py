"""ELF native-runtime fingerprinting.

The ELF pipeline historically tagged every native ELF as ``Framework.NATIVE`` and
never fingerprinted the toolchain — so a Rust/Go/Tauri ELF read as plain C/C++. The
byte-pattern detectors in :mod:`chimera.frameworks.native_pe` are platform
independent (they match panic strings, cargo paths, go.buildinfo, Tauri markers —
none of which are PE specific), so this module simply reuses them in an
ELF-appropriate priority order. Mach-O has its own :mod:`native_macho`.
"""

from __future__ import annotations

from typing import Optional

from chimera.frameworks.native_pe import _detect_go, _detect_rust, _detect_tauri


def detect_elf_runtime(data: bytes) -> Optional[tuple[str, str]]:
    """Return ``(framework_value, detail)`` for a native ELF, or ``None``.

    Tauri is tried before Rust (Tauri *is* Rust, but the specific tag is more
    useful); Go is unambiguous and cheap. .NET/VB markers are PE-only, so they are
    intentionally not consulted here.
    """
    for detector in (_detect_tauri, _detect_go, _detect_rust):
        hit = detector(data)
        if hit:
            return hit
    return None
