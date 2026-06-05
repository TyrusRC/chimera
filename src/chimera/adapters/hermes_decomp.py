"""hermes-decomp adapter — Rust-based React Native Hermes decompiler.

This is **not** the same tool as `hermes-dec` (P1 Security, Python). The
`hermes-decomp` project (SymbioticSec, 2026, MIT) ships a Rust binary
that recovers actual JavaScript-shaped control flow with closures and
emits comparable output across HBC versions 40-99 — the bytecode range
covering modern React Native bundles. We keep both adapters because:

- hermes-dec is fast disassembly, useful for triage and grep-able output.
- hermes-decomp is a slower but readable decompile — analyst-grade.

Auto-detection at use-site can pick either; this adapter does not assume
hermes-decomp is the default.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class HermesDecompAdapter(BackendAdapter):
    def __init__(self, binary: str | None = None) -> None:
        self._bin = (
            binary
            or os.environ.get("CHIMERA_HERMES_DECOMP_BIN")
            or shutil.which("hermes-decomp")
        )

    def name(self) -> str:
        return "hermes_decomp"

    def is_available(self) -> bool:
        return bool(self._bin)

    def supported_formats(self) -> list[str]:
        return ["hbc", "bundle"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = (
            Path(binary_path).stat().st_size / (1024 * 1024)
            if Path(binary_path).exists() else 5
        )
        return ResourceRequirement(
            memory_mb=max(768, int(size_mb * 8)),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(30, int(size_mb * 6)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if not self.is_available():
            return {"available": False, "decompiled": False,
                    "error": "hermes-decomp not on PATH"}
        bundle = Path(binary_path)
        output_dir = Path(
            options.get("output_dir") or bundle.parent / f"{bundle.stem}_hermes_decomp"
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "decompiled.js"

        cmd = [self._bin, "decompile", str(bundle), "-o", str(output_file)]
        timeout = int(options.get("timeout", 300))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"available": True, "decompiled": False, "error": "timeout"}
        err_text = stderr.decode(errors="replace")
        decompiled = output_file.exists() and output_file.stat().st_size > 0
        return {
            "available": True,
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "output_file": str(output_file),
            "decompiled": decompiled,
            "size": output_file.stat().st_size if decompiled else 0,
            "error": err_text[-2000:] if proc.returncode != 0 and err_text else None,
        }

    async def cleanup(self) -> None:
        pass


def detect_hbc(unpack_dir: str | Path) -> Path | None:
    """Locate a Hermes bytecode bundle inside an unpacked APK / IPA tree.

    React Native bundles ship as `index.android.bundle` (APK assets) or
    `main.jsbundle` (IPA). Both can be either raw JS or HBC; we treat
    "HBC" as "first bytes don't look like ASCII source."
    """
    candidates: list[Path] = []
    root = Path(unpack_dir)
    for pat in ("index.android.bundle", "main.jsbundle", "*.hbc"):
        candidates.extend(root.rglob(pat))
    for path in candidates:
        try:
            with open(path, "rb") as fh:
                head = fh.read(8)
            # HBC magic varies by version; raw JS bundles start with ASCII.
            if head and head[0] >= 0x80:
                return path
            if head.startswith(b"\xc6\x1f\xbc"):  # observed HBC magic
                return path
        except OSError:
            continue
    return None
