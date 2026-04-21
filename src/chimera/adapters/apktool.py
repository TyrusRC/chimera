"""apktool adapter — full APK resource + smali decode (beyond jadx)."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class ApktoolAdapter(BackendAdapter):
    def name(self) -> str:
        return "apktool"

    def is_available(self) -> bool:
        return shutil.which("apktool") is not None

    def supported_formats(self) -> list[str]:
        return ["apk", "aab"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 10
        mem = max(512, int(size_mb * 8))
        seconds = max(10, int(size_mb * 1))
        return ResourceRequirement(
            memory_mb=mem, category=ToolCategory.LIGHT, estimated_seconds=seconds
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = Path(binary_path).parent / f"{Path(binary_path).stem}_apktool"
        output_dir = Path(output_dir)
        # apktool refuses to overwrite non-empty dirs unless -f is given.
        cmd = ["apktool", "d", "-s", "-f", "-o", str(output_dir), binary_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        smali_dir = output_dir / "smali"
        res_dir = output_dir / "res"
        manifest = output_dir / "AndroidManifest.xml"
        net_config = None
        net_cfg_candidate = output_dir / "res" / "xml" / "network_security_config.xml"
        if net_cfg_candidate.exists():
            net_config = str(net_cfg_candidate)

        result = {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "smali_dir": str(smali_dir) if smali_dir.exists() else None,
            "res_dir": str(res_dir) if res_dir.exists() else None,
            "manifest_path": str(manifest) if manifest.exists() else None,
            "network_security_config_path": net_config,
            "strings_xml_files": sorted(
                str(p) for p in output_dir.rglob("strings.xml")
            ),
        }
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        return result

    async def cleanup(self) -> None:
        pass
