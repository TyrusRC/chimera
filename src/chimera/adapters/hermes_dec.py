"""hermes-dec adapter — Hermes bytecode (.hbc) decompilation for React Native bundles."""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class HermesDecAdapter(BackendAdapter):
    def name(self) -> str:
        return "hermes_dec"

    def is_available(self) -> bool:
        return shutil.which("hermes-dec") is not None

    def supported_formats(self) -> list[str]:
        return ["hbc", "bundle"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 5
        return ResourceRequirement(
            memory_mb=max(512, int(size_mb * 5)),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(15, int(size_mb * 3)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        bundle = Path(binary_path)
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = bundle.parent / f"{bundle.stem}_hermes_dec"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "decompiled.js"

        proc = await asyncio.create_subprocess_exec(
            "hermes-dec", str(bundle), "-o", str(output_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        err_text = stderr.decode(errors="replace")

        if output_file.exists() and output_file.stat().st_size > 0 and proc.returncode == 0:
            return {
                "return_code": proc.returncode,
                "output_dir": str(output_dir),
                "output_file": str(output_file),
                "decompiled": True,
                "size": output_file.stat().st_size,
                "hermes_bytecode_version": _parse_bytecode_version(err_text),
                "error": None,
            }

        return {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "output_file": str(output_file),
            "decompiled": False,
            "size": 0,
            "hermes_bytecode_version": _parse_bytecode_version(err_text),
            "error": err_text[-2000:] if err_text else None,
        }

    async def cleanup(self) -> None:
        pass


def _parse_bytecode_version(stderr: str) -> int | None:
    m = re.search(r"bytecode version[:\s]+(\d+)", stderr or "", re.IGNORECASE)
    return int(m.group(1)) if m else None
