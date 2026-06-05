"""oatdump2binexport — Android OAT to BinExport bridge for BinDiff.

Background. Phrack 72:13 (Bleier & Lindorfer, Aug 2025) demonstrated that
running an APK through `dex2oat` to produce an OAT/ELF image and then
converting that image into a BinExport feed for BinDiff catches code
similarities that survive DEX-level obfuscation (renaming, control-flow
flattening at the smali layer, etc.). The trick: DEX obfuscators do not
re-obfuscate the AOT-compiled native form, so structural diffing at the
OAT layer recovers ground truth the smali view loses.

This adapter is a thin subprocess wrapper around the community
`oatdump2binexport` binary. It's opt-in — the chimera wheel does not
bundle the tool — and detected via PATH or `$CHIMERA_OATDUMP2BINEXPORT_BIN`.

Reference:
  Phrack 72:13 — Bleier & Lindorfer, "Diffing Android Native Code via OAT",
  Aug 2025.
  Community tool: oatdump2binexport (see Phrack for tracking repo).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


class OatDumpAdapter(BackendAdapter):
    """External-process wrapper around the `oatdump2binexport` binary.

    Activation: opt-in. `is_available()` returns False unless the binary
    is found, so default chimera workflows pay no cost.
    """

    ENV_VAR = "CHIMERA_OATDUMP2BINEXPORT_BIN"

    def __init__(self, binary: Optional[str] = None, timeout_s: int = 600):
        self._binary = (
            binary
            or os.environ.get(self.ENV_VAR)
            or shutil.which("oatdump2binexport")
        )
        self._timeout_s = timeout_s

    def name(self) -> str:
        return "oatdump2binexport"

    def is_available(self) -> bool:
        return bool(self._binary) and Path(self._binary).is_file() and \
               os.access(self._binary, os.X_OK)

    def binary_path(self) -> Optional[str]:
        return self._binary

    def supported_formats(self) -> list[str]:
        return ["oat", "apk"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        # oatdump2binexport walks the OAT ELF and writes a protobuf —
        # roughly 3× input size in working memory, no GPU, fast.
        try:
            size_mb = max(1, Path(binary_path).stat().st_size // (1024 * 1024))
        except OSError:
            size_mb = 32
        return ResourceRequirement(
            memory_mb=max(256, size_mb * 3),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(5, size_mb // 4),
        )

    async def analyze(self, oat_path: str, options: dict) -> dict:
        """Convert an OAT file to a BinExport protobuf.

        Options:
          out  — explicit output `.BinExport` path; defaults to
                 `<oat_path>.BinExport`.
        Returns a dict with `available`, `binexport_path`, `function_count`,
        and `error` keys. `function_count` is best-effort (counted from
        stdout when oatdump2binexport reports it) and may be 0 even on
        success when the tool is silent.
        """
        if not self.is_available():
            return {
                "available": False,
                "binexport_path": None,
                "function_count": 0,
                "error": (
                    "oatdump2binexport binary not found on PATH and "
                    f"{self.ENV_VAR} not set"
                ),
            }
        oat = Path(oat_path)
        if not oat.exists():
            return {
                "available": True,
                "binexport_path": None,
                "function_count": 0,
                "error": f"OAT input does not exist: {oat_path}",
            }
        out = Path(options.get("out") or str(oat) + ".BinExport")
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(self._binary),
            "--in", str(oat),
            "--out", str(out),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout_s,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "available": True,
                    "binexport_path": None,
                    "function_count": 0,
                    "error": f"oatdump2binexport timed out after {self._timeout_s}s",
                }
        except OSError as exc:
            return {
                "available": True,
                "binexport_path": None,
                "function_count": 0,
                "error": f"failed to spawn oatdump2binexport: {exc}",
            }
        if proc.returncode != 0:
            return {
                "available": True,
                "binexport_path": None,
                "function_count": 0,
                "error": (stderr.decode("utf-8", errors="replace")[:500]
                          or f"oatdump2binexport exit={proc.returncode}"),
            }
        return {
            "available": True,
            "binexport_path": str(out) if out.exists() else None,
            "function_count": _parse_function_count(stdout.decode("utf-8", errors="replace")),
            "error": None,
        }

    async def cleanup(self) -> None:
        # Stateless wrapper, nothing to release.
        pass


def _parse_function_count(stdout: str) -> int:
    """Best-effort scrape of "N functions" from oatdump2binexport stdout.

    The community tool's output format varies across versions; we look
    for the most common "<N> functions" / "functions: <N>" patterns and
    fall back to 0 when nothing matches. Callers should treat 0 as
    "unknown", not "definitely empty".
    """
    import re
    for line in stdout.splitlines():
        m = re.search(r"(\d+)\s+functions?\b", line)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
        m = re.search(r"functions?\s*[:=]\s*(\d+)", line, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return 0
