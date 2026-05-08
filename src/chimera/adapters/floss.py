"""FLOSS (FLARE Obfuscated String Solver) adapter.

Recovers stack/tight/decoded strings from PE/ELF binaries — the strings
malware authors hide from static `strings` output. Slow on dense
binaries; default 90s timeout, killable via `--no-floss`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


class FlossAdapter(BackendAdapter):
    def __init__(self):
        self._floss_bin = shutil.which("floss")

    def name(self) -> str:
        return "floss"

    def is_available(self) -> bool:
        return self._floss_bin is not None

    def supported_formats(self) -> list[str]:
        return ["pe32", "pe64", "elf", "elf_standalone"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = (
            Path(binary_path).stat().st_size / (1024 * 1024)
            if Path(binary_path).exists() else 5
        )
        return ResourceRequirement(
            memory_mb=max(1024, int(size_mb * 24)),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(15, int(size_mb * 4)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if not self.is_available():
            return {
                "available": False, "decoded": [], "stack": [], "tight": [],
                "stats": {"decoded_count": 0, "stack_count": 0, "tight_count": 0},
            }

        cmd = [self._floss_bin, "-j", "--no", "static", binary_path]
        timeout = int(options.get("timeout", 90))

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
                "available": True, "decoded": [], "stack": [], "tight": [],
                "stats": {"decoded_count": 0, "stack_count": 0, "tight_count": 0},
                "error": "timeout",
            }

        if proc.returncode != 0:
            return {
                "available": True, "decoded": [], "stack": [], "tight": [],
                "stats": {"decoded_count": 0, "stack_count": 0, "tight_count": 0},
                "error": stderr.decode(errors="replace")[-1000:],
            }

        try:
            payload = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return {
                "available": True, "decoded": [], "stack": [], "tight": [],
                "stats": {"decoded_count": 0, "stack_count": 0, "tight_count": 0},
                "error": str(exc),
            }

        return _normalize(payload)

    async def cleanup(self) -> None:
        pass


def _normalize(payload: dict) -> dict:
    """Flatten FLOSS's nested `strings` block into the result schema."""
    strings = payload.get("strings") or {}

    decoded_raw = strings.get("decoded_strings") or []
    stack_raw = strings.get("stack_strings") or []
    tight_raw = strings.get("tight_strings") or []

    decoded = [
        {
            "value": _str(s.get("string")),
            "address": _hex_or_none(s.get("address")),
            "encoding": s.get("encoding"),
        }
        for s in decoded_raw if s.get("string")
    ]
    stack = [
        {
            "value": _str(s.get("string")),
            "function": _hex_or_none(s.get("function_address")),
        }
        for s in stack_raw if s.get("string")
    ]
    tight = [
        {
            "value": _str(s.get("string")),
            "function": _hex_or_none(s.get("function_address")),
        }
        for s in tight_raw if s.get("string")
    ]

    return {
        "available": True,
        "decoded": decoded,
        "stack": stack,
        "tight": tight,
        "stats": {
            "decoded_count": len(decoded),
            "stack_count": len(stack),
            "tight_count": len(tight),
        },
    }


def _str(v) -> str:
    if v is None:
        return ""
    return v if isinstance(v, str) else str(v)


def _hex_or_none(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, int):
        return hex(v)
    return str(v)
