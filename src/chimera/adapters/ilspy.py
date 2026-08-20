"""ILSpy adapter — decompile .NET assemblies to C# source.

Targets DOTNET_PE only. ILSpy's `ilspycmd` is the cross-platform CLI;
we don't ship dnSpy support because dnSpy on Linux requires Mono+winforms
shims that are brittle.

Output is per-type `.cs` files under a temp dir; the adapter walks them
and returns a flat list of `{namespace, name, file, size_bytes}` records.
The actual C# text is left on disk — pipelines truncate per-type when
embedding in reports.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory
from chimera.dotnet.toolpath import find_dotnet_tool

logger = logging.getLogger(__name__)


class IlspyAdapter(BackendAdapter):
    def __init__(self):
        # ilspycmd installs to ~/.dotnet/tools, which is not on the default
        # PATH — so a launched MCP server would otherwise never find it.
        self._ilspy_bin = find_dotnet_tool("ilspycmd")

    def name(self) -> str:
        return "ilspy"

    def is_available(self) -> bool:
        return self._ilspy_bin is not None

    def supported_formats(self) -> list[str]:
        return ["dotnet_pe"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = (
            Path(binary_path).stat().st_size / (1024 * 1024)
            if Path(binary_path).exists() else 5
        )
        return ResourceRequirement(
            memory_mb=max(512, int(size_mb * 16)),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(10, int(size_mb * 2)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Decompile a .NET assembly. Requires `output_dir` in options."""
        if not self.is_available():
            return {
                "available": False,
                "assembly": Path(binary_path).stem,
                "types": [],
                "type_count": 0,
            }

        out_dir_str = options.get("output_dir")
        if not out_dir_str:
            return {
                "available": True,
                "assembly": Path(binary_path).stem,
                "types": [],
                "type_count": 0,
                "error": "output_dir not provided",
            }
        out_dir = Path(out_dir_str)
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [self._ilspy_bin, binary_path, "-o", str(out_dir)]
        timeout = int(options.get("timeout", 120))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "available": True,
                "assembly": Path(binary_path).stem,
                "types": [],
                "type_count": 0,
                "error": "timeout",
            }

        if proc.returncode != 0:
            return {
                "available": True,
                "assembly": Path(binary_path).stem,
                "types": [],
                "type_count": 0,
                "error": stderr.decode(errors="replace")[-1000:],
            }

        return _walk_output(out_dir, Path(binary_path).stem)

    async def cleanup(self) -> None:
        pass


# Cap per-type source read so a pathological assembly can't balloon the model.
_MAX_DECOMPILED_BYTES = 256 * 1024


def _walk_output(out_dir: Path, assembly_stem: str) -> dict:
    """Walk an ILSpy output directory and emit per-type metadata + source."""
    types: list[dict] = []
    if out_dir.exists():
        for cs_file in sorted(out_dir.rglob("*.cs")):
            rel = cs_file.relative_to(out_dir)
            # Namespace = directory parts under out_dir; type name = file stem
            namespace = ".".join(rel.parent.parts) if rel.parent.parts else ""
            try:
                size = cs_file.stat().st_size
            except OSError:
                continue
            # Read the emitted C# so it reaches FunctionInfo.decompiled instead
            # of being left on disk (the PE pipeline reads the "decompiled" key).
            decompiled = None
            try:
                with cs_file.open("r", encoding="utf-8", errors="replace") as fh:
                    decompiled = fh.read(_MAX_DECOMPILED_BYTES)
                if size > _MAX_DECOMPILED_BYTES:
                    decompiled += "\n// … truncated by chimera (type source exceeds cap)\n"
            except OSError:
                decompiled = None
            types.append({
                "namespace": namespace,
                "name": cs_file.stem,
                "file": str(cs_file),
                "size_bytes": size,
                "decompiled": decompiled,
            })
    return {
        "available": True,
        "assembly": assembly_stem,
        "types": types,
        "type_count": len(types),
    }
