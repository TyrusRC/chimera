"""Ghidra headless adapter — deep decompilation, P-Code, type recovery, FidDb."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class GhidraAdapter(BackendAdapter):
    def __init__(self, ghidra_home: str | None = None, max_mem: str = "4g"):
        self._ghidra_home_override = ghidra_home
        self._max_mem = max_mem
        self._temp_dirs: list[str] = []

    def name(self) -> str:
        return "ghidra"

    def is_available(self) -> bool:
        return self._ghidra_home is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "dex", "fat", "dylib"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 10
        mem = max(2048, int(size_mb * 40))
        seconds = max(30, int(size_mb * 5))
        return ResourceRequirement(memory_mb=mem, category=ToolCategory.HEAVY, estimated_seconds=seconds)

    @property
    def _ghidra_home(self) -> Optional[str]:
        if self._ghidra_home_override:
            return self._ghidra_home_override
        env = os.environ.get("GHIDRA_HOME")
        if env and Path(env).exists():
            return env
        candidates = ["/opt/ghidra", "/usr/local/ghidra", Path.home() / "ghidra"]
        for c in candidates:
            p = Path(c)
            if p.exists() and (p / "support" / "analyzeHeadless").exists():
                return str(p)
            if p.parent.exists():
                for child in sorted(p.parent.glob("ghidra_*"), reverse=True):
                    if (child / "support" / "analyzeHeadless").exists():
                        return str(child)
        return None

    @property
    def _analyze_headless(self) -> str:
        home = self._ghidra_home
        if not home:
            raise RuntimeError("Ghidra not found. Set GHIDRA_HOME environment variable.")
        path = Path(home) / "support" / "analyzeHeadless"
        if not path.exists():
            path = Path(home) / "support" / "analyzeHeadless.bat"
        return str(path)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        mode = options.get("mode", "decompile")
        project_dir = options.get("project_dir")
        if project_dir is None:
            project_dir = tempfile.mkdtemp(prefix="chimera_ghidra_")
            self._temp_dirs.append(project_dir)
        project_name = f"chimera_{Path(binary_path).stem}"
        output_dir = Path(project_dir) / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self._analyze_headless, project_dir, project_name,
            "-import", binary_path, "-overwrite",
            "-max-cpu", "2", f"-Xmx{self._max_mem}",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        result = {
            "return_code": proc.returncode,
            "project_dir": project_dir,
            "output_dir": str(output_dir),
        }
        for output_file in output_dir.glob("*.json"):
            try:
                result[output_file.stem] = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                result[output_file.stem] = output_file.read_text()
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        return result

    async def cleanup(self) -> None:
        for d in self._temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._temp_dirs.clear()
