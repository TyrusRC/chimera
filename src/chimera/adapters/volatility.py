"""Volatility 3 adapter — runs forensic plugins against a memory image.

We shell out to `vol` because Volatility 3's Python API is tightly
coupled to its global config singleton, which makes embedding ugly.
Subprocess + JSON output keeps the boundary clean and matches the
pattern used for capa/floss.

Skip-graceful: if `vol` is missing, the adapter returns
`available=False` and the pipeline skips memory-side phases without
crashing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


def _resolve_vol_binary() -> str | None:
    """Find a Volatility 3 executable on PATH."""
    for candidate in ("vol", "vol.py", "volatility3"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


class VolatilityAdapter(BackendAdapter):
    def __init__(self):
        self._vol_bin = _resolve_vol_binary()

    def name(self) -> str:
        return "volatility"

    def is_available(self) -> bool:
        return self._vol_bin is not None

    def supported_formats(self) -> list[str]:
        return ["memory_lime", "memory_raw"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = (
            Path(binary_path).stat().st_size / (1024 * 1024)
            if Path(binary_path).exists() else 1024
        )
        # Volatility loads symbol tables and walks the image — RAM scales
        # with image size (and Linux symbol coverage).
        return ResourceRequirement(
            memory_mb=max(2048, int(size_mb * 1.5)),
            category=ToolCategory.HEAVY,
            estimated_seconds=max(60, int(size_mb / 32)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Run a single Volatility plugin and return its parsed output.

        `options` keys:
          - `plugin`  (str, required) — e.g. "linux.pslist.PsList"
          - `args`    (list[str], optional) — extra args appended after the plugin
          - `timeout` (int, optional) — default 300s
        """
        if not self.is_available():
            return {
                "available": False,
                "plugin": options.get("plugin"),
                "rows": [],
            }

        plugin = options.get("plugin")
        if not plugin:
            return {
                "available": True,
                "plugin": None,
                "rows": [],
                "error": "options['plugin'] is required",
            }

        cmd = [self._vol_bin, "-f", binary_path, "-r", "json", plugin]
        extra = options.get("args") or []
        if extra:
            cmd.extend(extra)
        timeout = int(options.get("timeout", 300))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "available": True, "plugin": plugin, "rows": [],
                "error": "timeout",
            }

        if proc.returncode != 0:
            return {
                "available": True, "plugin": plugin, "rows": [],
                "error": stderr.decode(errors="replace")[-2000:],
            }

        try:
            payload = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return {
                "available": True, "plugin": plugin, "rows": [],
                "error": f"json decode failed: {exc}",
            }

        # Volatility 3 emits either a top-level array OR an object with
        # the rows nested under a key (depending on plugin version).
        rows: list = []
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            # Check common keys
            for key in ("rows", "data", "results"):
                if isinstance(payload.get(key), list):
                    rows = payload[key]
                    break

        return {
            "available": True,
            "plugin": plugin,
            "rows": rows,
            "stats": {"row_count": len(rows)},
        }

    async def cleanup(self) -> None:
        pass
