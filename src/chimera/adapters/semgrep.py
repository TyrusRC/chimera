"""Semgrep adapter — pattern-based source code scanning."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class SemgrepAdapter(BackendAdapter):
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def supported_formats(self) -> list[str]:
        return ["java", "kotlin", "swift", "objc", "javascript"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=512, category=ToolCategory.LIGHT, estimated_seconds=30)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Run semgrep on a directory of decompiled source code."""
        rules = options.get("rules", "auto")
        output_format = options.get("format", "json")

        cmd = [
            "semgrep", "scan",
            "--config", rules,
            "--json",
            "--quiet",
            binary_path,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        try:
            results = json.loads(stdout.decode()) if stdout else {}
        except json.JSONDecodeError:
            results = {}

        return {
            "return_code": proc.returncode,
            "results": results.get("results", []),
            "errors": results.get("errors", []),
        }

    async def cleanup(self) -> None:
        pass
