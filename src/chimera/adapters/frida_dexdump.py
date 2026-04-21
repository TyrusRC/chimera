"""frida-dexdump adapter — stub (availability-only in v1).

Actual extraction requires a running device and belongs to Sub-project 2's
dynamic tier (see 2026-04-18 pattern-db-deobfuscation-engine-design.md).
"""

from __future__ import annotations

import shutil

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class FridaDexdumpAdapter(BackendAdapter):
    def name(self) -> str:
        return "frida-dexdump"

    def is_available(self) -> bool:
        return shutil.which("frida-dexdump") is not None

    def supported_formats(self) -> list[str]:
        return ["apk", "dex"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(
            memory_mb=512, category=ToolCategory.LIGHT, estimated_seconds=30
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        raise NotImplementedError(
            "frida-dexdump requires a running device; dynamic extraction is deferred to "
            "Sub-project 2 (pattern-db-deobfuscation-engine). Use the static adapters "
            "for packed-DEX analysis or run frida-dexdump manually against a device."
        )

    async def cleanup(self) -> None:
        pass
