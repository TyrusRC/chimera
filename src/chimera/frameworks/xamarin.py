"""Xamarin analyzer — .NET assembly extraction and decompilation."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


class XamarinAnalyzer:
    def find_assemblies(self, unpack_dir: Path) -> list[Path]:
        """Find .NET assemblies in the unpacked app."""
        assemblies_dir = Path(unpack_dir) / "assemblies"
        if assemblies_dir.exists():
            return sorted(assemblies_dir.glob("*.dll"))
        return []

    def looks_obfuscated(self, assembly_names: list[str]) -> bool:
        """Check if assembly names suggest obfuscation."""
        if not assembly_names:
            return False
        short_names = sum(1 for n in assembly_names if len(n) <= 2)
        return short_names / len(assembly_names) > 0.5

    async def decompile(self, dll_path: Path, output_dir: Path) -> dict:
        """Decompile a .NET assembly using ILSpy CLI."""
        tool = shutil.which("ilspycmd") or shutil.which("ilspy")
        if not tool:
            return {"error": "ILSpy CLI not installed", "decompiled": False}

        output_dir.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            tool, str(dll_path), "-o", str(output_dir), "-p",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        cs_files = list(output_dir.rglob("*.cs"))
        return {
            "decompiled": proc.returncode == 0,
            "output_dir": str(output_dir),
            "file_count": len(cs_files),
            "error": stderr.decode(errors="replace")[:500] if proc.returncode != 0 else None,
        }

    async def deobfuscate(self, dll_path: Path, output_path: Path) -> dict:
        """Run de4dot to remove .NET obfuscation."""
        if not shutil.which("de4dot"):
            return {"error": "de4dot not installed", "deobfuscated": False}

        proc = await asyncio.create_subprocess_exec(
            "de4dot", str(dll_path), "-o", str(output_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return {
            "deobfuscated": proc.returncode == 0 and output_path.exists(),
            "output": str(output_path),
        }
