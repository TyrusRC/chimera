"""jadx adapter — Java/Kotlin decompilation from DEX (primary Android decompiler)."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class JadxAdapter(BackendAdapter):
    def name(self) -> str:
        return "jadx"

    def is_available(self) -> bool:
        return shutil.which("jadx") is not None

    def supported_formats(self) -> list[str]:
        return ["apk", "dex", "aab"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 10
        mem = max(512, int(size_mb * 10))
        seconds = max(10, int(size_mb * 2))
        return ResourceRequirement(memory_mb=mem, category=ToolCategory.LIGHT, estimated_seconds=seconds)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = Path(binary_path).parent / f"{Path(binary_path).stem}_jadx"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "jadx", "--deobf", "--deobf-use-sourcename", "--show-bad-code",
            "--threads-count", "2", "--output-dir", str(output_dir), binary_path,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        result = {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "sources_dir": str(output_dir / "sources"),
            "resources_dir": str(output_dir / "resources"),
        }
        sources = output_dir / "sources"
        if sources.exists():
            java_files = list(sources.rglob("*.java"))
            result["decompiled_files"] = len(java_files)
            result["packages"] = sorted({
                str(f.parent.relative_to(sources)).replace("/", ".").replace("\\", ".")
                for f in java_files
            })
        else:
            result["decompiled_files"] = 0
            result["packages"] = []
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        return result

    async def cleanup(self) -> None:
        pass
