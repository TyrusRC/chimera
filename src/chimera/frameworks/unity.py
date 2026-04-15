"""Unity IL2CPP analyzer — metadata recovery and native binary annotation."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_IL2CPP_METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"


class UnityAnalyzer:
    def find_il2cpp_binary(self, unpack_dir: Path) -> Path | None:
        """Find libil2cpp.so or GameAssembly.framework."""
        unpack_dir = Path(unpack_dir)
        for arch in ["arm64-v8a", "armeabi-v7a"]:
            p = unpack_dir / "lib" / arch / "libil2cpp.so"
            if p.exists():
                return p
        # iOS
        ga = unpack_dir / "Frameworks" / "GameAssembly.framework" / "GameAssembly"
        if ga.exists():
            return ga
        return None

    def find_metadata(self, unpack_dir: Path) -> Path | None:
        """Find global-metadata.dat with valid magic bytes."""
        for meta in Path(unpack_dir).rglob("global-metadata.dat"):
            if meta.stat().st_size > 100:
                magic = meta.read_bytes()[:4]
                if magic == _IL2CPP_METADATA_MAGIC:
                    return meta
        return None

    async def run_il2cppdumper(self, binary_path: Path, metadata_path: Path,
                                output_dir: Path) -> dict:
        """Run il2cppdumper to extract class/method/field names."""
        if not shutil.which("Il2CppDumper"):
            return {"error": "Il2CppDumper not installed", "dumped": False}

        output_dir.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "Il2CppDumper", str(binary_path), str(metadata_path), str(output_dir),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        dump_cs = output_dir / "dump.cs"
        script_py = output_dir / "script.json"

        return {
            "dumped": dump_cs.exists(),
            "output_dir": str(output_dir),
            "dump_file": str(dump_cs) if dump_cs.exists() else None,
            "ghidra_script": str(script_py) if script_py.exists() else None,
            "error": stderr.decode(errors="replace")[:500] if proc.returncode != 0 else None,
        }
