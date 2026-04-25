"""swift-demangle adapter — demangle Swift mangled symbols via the swift-demangle CLI."""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


_MANGLED_RE = re.compile(r"^(_\$[Ss]|_T0|_T)\S+$")
_MANGLED_TOKEN_RE = re.compile(r"(_\$[Ss]|_T0|_T)[A-Za-z0-9_$]+")


class SwiftDemangleAdapter(BackendAdapter):
    def name(self) -> str:
        return "swift_demangle"

    def is_available(self) -> bool:
        return shutil.which("swift-demangle") is not None

    def supported_formats(self) -> list[str]:
        return ["text"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(
            memory_mb=128, category=ToolCategory.LIGHT, estimated_seconds=5,
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        path = Path(binary_path)
        names: list[str] = []
        if path.exists():
            try:
                names = [
                    line.strip()
                    for line in path.read_text(errors="replace").splitlines()
                    if line.strip()
                ]
            except OSError:
                names = []
        result = await self.demangle_batch(names)
        return {
            "return_code": 0,
            "input_count": len(names),
            "demangled_count": sum(1 for k, v in result.items() if v != k),
            "demangle_map": result,
        }

    async def demangle_batch(self, names: list[str]) -> dict[str, str]:
        if not names:
            return {}
        # Dedupe preserving first-seen order.
        seen: dict[str, None] = {}
        for n in names:
            if n not in seen:
                seen[n] = None
        deduped = list(seen)
        # Subprocess wiring is added in Task 2.
        return {name: name for name in deduped}

    async def cleanup(self) -> None:
        pass
