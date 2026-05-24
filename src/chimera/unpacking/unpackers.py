"""Concrete unpackers + manual-recovery guidance for protected binaries.

Each ``Unpacker`` is a small adapter around a third-party tool (``upx``
is the only auto-supported one today). Adding more is a matter of
implementing ``run(src, dst) -> UnpackResult``.

For VM-protectors (Themida, VMProtect) we deliberately do *not* ship an
auto-unpacker — the open-source unpackers in the wild are
target-specific and often produce subtly-broken binaries. We surface
documentation instead so the analyst knows what tool to reach for.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class UnpackError(Exception):
    """Unpacking failed — caller decides whether to surface or retry."""


@dataclass
class UnpackResult:
    output: Path
    original_size: int
    unpacked_size: int
    notes: str = ""


@dataclass
class Unpacker:
    """One concrete tool wrapper. ``run`` is the entrypoint."""
    name: str
    description: str
    tool: str         # the binary we shell out to; must exist on PATH
    applies_to: tuple[str, ...]    # one of "upx", "themida", "vmprotect"...

    def run(self, src: Path, dst: Path) -> UnpackResult:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# UPX
# ---------------------------------------------------------------------------


@dataclass
class UPXUnpacker(Unpacker):
    name: str = "upx"
    description: str = "Calls `upx -d` to inflate the packed binary."
    tool: str = "upx"
    applies_to: tuple[str, ...] = ("upx",)

    def run(self, src: Path, dst: Path) -> UnpackResult:
        binary = shutil.which(self.tool)
        if binary is None:
            raise UnpackError(
                "upx not found on PATH. Install with "
                "`apt-get install upx` (or equivalent) and re-run."
            )
        # UPX rewrites in-place by default, so we copy first.
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            dst.unlink()
        shutil.copy2(src, dst)
        result = subprocess.run(
            [binary, "-d", "-q", str(dst)],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode != 0:
            # UPX returns 2 when the input isn't packed.
            tail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
            raise UnpackError(
                f"upx -d failed (rc={result.returncode}): {' | '.join(tail)}"
            )
        return UnpackResult(
            output=dst,
            original_size=src.stat().st_size,
            unpacked_size=dst.stat().st_size,
            notes=f"upx -d ok ({result.stdout.strip().splitlines()[-1:][0] if result.stdout else ''})",
        )


_UNPACKERS: dict[str, Unpacker] = {
    "upx": UPXUnpacker(),
}


_MANUAL_GUIDANCE: dict[str, str] = {
    "themida": (
        "Themida/WinLicense uses a VM + code-rewriting engine. No reliable\n"
        "open-source unpacker exists. Common analyst path:\n"
        "  1. Dump the running process with Scylla once the unpacked code\n"
        "     reaches the OEP (Original Entry Point).\n"
        "  2. Reconstruct the import table via Scylla's IAT fixer.\n"
        "  3. Re-analyse the dump with `chimera analyze` — pass --no-ghidra\n"
        "     on first pass; Ghidra struggles with reconstructed IATs.\n"
        "  4. Optional: feed the dump through DeThemidaUtility for partial\n"
        "     handler de-virtualisation."
    ),
    "vmprotect": (
        "VMProtect virtualises selected functions into custom bytecode.\n"
        "No automated unpacker recovers original semantics. Common path:\n"
        "  1. Identify VMProtect's `vm_entry` thunks (chimera's signature\n"
        "     matcher tags these as `library` when present).\n"
        "  2. Use VMPDump / VMProtect-Imports-Fixer for IAT recovery.\n"
        "  3. The virtualised functions stay opaque — analyse them via\n"
        "     dynamic tracing (`chimera attach --pid`) rather than static."
    ),
    "aspack": (
        "ASPack is dump-friendly. Recommended path:\n"
        "  1. Set a breakpoint on the final `popad; jmp <oep>` tail in the\n"
        "     ASPack stub (look for `61 e9 ?? ?? ?? ??`).\n"
        "  2. Dump with Scylla at that breakpoint.\n"
        "  3. The IAT is intact; no fixer needed."
    ),
    "pecompact": (
        "PECompact unpacking generally works with `de4dot` or quickunpack;\n"
        "neither is bundled. Manual:\n"
        "  1. Run-to-OEP via VEH-based unpacker.\n"
        "  2. Dump + fix imports."
    ),
    "mpress": (
        "MPRESS has a published `mpress -d` mode but only the original\n"
        "vendor binary ships it. Try `qunpack` or manual dump-at-OEP."
    ),
    "enigma": (
        "Enigma Protector is anti-debug heavy; manual unpacking required.\n"
        "Start with chimera's anti-debug bypass recipes:\n"
        "  chimera attach --pid <pid> --bypass anti_debug"
    ),
}


def unpacker_for(packer: str) -> Optional[Unpacker]:
    """Return the registered Unpacker for `packer`, case-insensitive."""
    key = (packer or "").strip().lower()
    return _UNPACKERS.get(key)


def guidance_for(packer: str) -> Optional[str]:
    key = (packer or "").strip().lower()
    return _MANUAL_GUIDANCE.get(key)


def run_unpacker(unpacker: Unpacker, src: Path, dst: Path) -> UnpackResult:
    return unpacker.run(src, dst)
