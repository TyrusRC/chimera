"""class-dump / dsdump adapter — ObjC header extraction from Mach-O binaries."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class ClassDumpAdapter(BackendAdapter):
    def name(self) -> str:
        return "class-dump"

    def is_available(self) -> bool:
        return (
            shutil.which("class-dump") is not None
            or shutil.which("dsdump") is not None
            or shutil.which("class-dump-swift") is not None
        )

    def supported_formats(self) -> list[str]:
        return ["macho", "fat"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=256, category=ToolCategory.LIGHT, estimated_seconds=15)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = Path(binary_path).parent / f"{Path(binary_path).stem}_headers"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        tool = self._find_tool()
        if not tool:
            return {"error": "No class-dump tool found", "headers": ""}

        if tool == "dsdump":
            return await self._run_dsdump(binary_path, output_dir)
        else:
            return await self._run_class_dump(tool, binary_path, output_dir)

    def _find_tool(self) -> str | None:
        for tool in ["dsdump", "class-dump", "class-dump-swift"]:
            if shutil.which(tool):
                return tool
        return None

    async def _run_class_dump(self, tool: str, binary_path: str, output_dir: Path) -> dict:
        cmd = [tool, "-H", "-o", str(output_dir), binary_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        headers = list(output_dir.rglob("*.h"))
        return {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "header_count": len(headers),
            "headers": [str(h) for h in headers],
            "error": stderr.decode(errors="replace")[-1000:] if proc.returncode != 0 else None,
        }

    async def _run_dsdump(self, binary_path: str, output_dir: Path) -> dict:
        cmd = ["dsdump", "--objc", "--verbose=5", binary_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        output_file = output_dir / "headers.h"
        output_file.write_bytes(stdout)

        classes = []
        for line in stdout.decode(errors="replace").splitlines():
            if line.startswith("@interface "):
                class_name = line.split()[1].split("(")[0].split(":")[0]
                classes.append(class_name)

        return {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "output_file": str(output_file),
            "header_count": 1 if stdout else 0,
            "classes": classes,
            "class_count": len(classes),
            "error": stderr.decode(errors="replace")[-1000:] if proc.returncode != 0 else None,
        }

    async def cleanup(self) -> None:
        pass
