"""AFL++ adapter — fuzzing native ARM libraries via QEMU user-mode."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


@dataclass
class FuzzCampaign:
    campaign_id: str
    binary: str
    input_dir: str
    output_dir: str
    process: Optional[asyncio.subprocess.Process] = None
    status: str = "pending"  # pending, running, stopped, completed


class AFLAdapter(BackendAdapter):
    def __init__(self):
        self._campaigns: dict[str, FuzzCampaign] = {}

    def name(self) -> str:
        return "afl++"

    def is_available(self) -> bool:
        return shutil.which("afl-fuzz") is not None

    def supported_formats(self) -> list[str]:
        return ["elf"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=1024, category=ToolCategory.HEAVY, estimated_seconds=3600)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Start a fuzzing campaign."""
        input_dir = options.get("input_dir")
        output_dir = options.get("output_dir")
        timeout_ms = options.get("timeout_ms", 1000)
        duration_seconds = options.get("duration", 300)
        qemu_mode = options.get("qemu", True)

        if not input_dir or not output_dir:
            return {"error": "input_dir and output_dir required"}

        Path(input_dir).mkdir(parents=True, exist_ok=True)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Create seed if input dir is empty
        seeds = list(Path(input_dir).glob("*"))
        if not seeds:
            (Path(input_dir) / "seed_0").write_bytes(b"AAAA")

        campaign_id = f"fuzz_{Path(binary_path).stem}_{len(self._campaigns)}"

        cmd = self._build_fuzz_command(binary_path, input_dir, output_dir,
                                        qemu_mode, timeout_ms)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._build_env(qemu_mode),
        )

        campaign = FuzzCampaign(
            campaign_id=campaign_id,
            binary=binary_path,
            input_dir=input_dir,
            output_dir=output_dir,
            process=proc,
            status="running",
        )
        self._campaigns[campaign_id] = campaign

        # Wait for duration then stop
        try:
            await asyncio.wait_for(proc.communicate(), timeout=duration_seconds)
            campaign.status = "completed"
        except asyncio.TimeoutError:
            proc.terminate()
            campaign.status = "stopped"

        return self._collect_results(campaign)

    def _build_fuzz_command(self, binary: str, input_dir: str, output_dir: str,
                            qemu_mode: bool, timeout_ms: int) -> list[str]:
        cmd = [
            "afl-fuzz",
            "-i", input_dir,
            "-o", output_dir,
            "-t", str(timeout_ms),
        ]
        if qemu_mode:
            cmd.append("-Q")
        cmd.extend(["--", binary, "@@"])
        return cmd

    def _build_env(self, qemu_mode: bool) -> dict:
        import os
        env = dict(os.environ)
        if qemu_mode:
            env["AFL_QEMU_CPU"] = "aarch64"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_NO_UI"] = "1"
        return env

    def _collect_results(self, campaign: FuzzCampaign) -> dict:
        output = Path(campaign.output_dir)
        crashes_dir = output / "default" / "crashes"
        hangs_dir = output / "default" / "hangs"

        crashes = sorted(crashes_dir.glob("id:*")) if crashes_dir.exists() else []
        hangs = sorted(hangs_dir.glob("id:*")) if hangs_dir.exists() else []

        return {
            "campaign_id": campaign.campaign_id,
            "status": campaign.status,
            "crashes": len(crashes),
            "hangs": len(hangs),
            "crash_files": [str(c) for c in crashes[:20]],
            "hang_files": [str(h) for h in hangs[:20]],
        }

    async def get_campaign_status(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": f"Campaign {campaign_id} not found"}
        return self._collect_results(campaign)

    async def cleanup(self) -> None:
        for campaign in self._campaigns.values():
            if campaign.process and campaign.process.returncode is None:
                campaign.process.terminate()
        self._campaigns.clear()
