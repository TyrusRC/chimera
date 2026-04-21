"""webcrack adapter — JavaScript AST-based deobfuscation.

Handles JSC / Cordova / minified RN bundles. Hermes bytecode is NOT in scope.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class WebcrackAdapter(BackendAdapter):
    def name(self) -> str:
        return "webcrack"

    def is_available(self) -> bool:
        return shutil.which("webcrack") is not None

    def supported_formats(self) -> list[str]:
        return ["js", "bundle"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(
            memory_mb=1024, category=ToolCategory.LIGHT, estimated_seconds=30
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = Path(binary_path).parent / f"{Path(binary_path).stem}_webcrack"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["webcrack", "-o", str(output_dir), binary_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        files = sorted(str(p) for p in output_dir.rglob("*.js"))
        result = {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "output_files": files,
            "file_count": len(files),
        }
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        return result

    async def cleanup(self) -> None:
        pass
