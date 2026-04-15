"""iOS device manager — wraps libimobiledevice + iproxy for device interaction."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Optional

from chimera.device.base import DeviceManager, DeviceInfo, DevicePlatform

logger = logging.getLogger(__name__)


class IOSDeviceManager(DeviceManager):
    @property
    def name(self) -> str:
        return "ios"

    @property
    def is_available(self) -> bool:
        return shutil.which("idevice_id") is not None

    async def list_devices(self) -> list[DeviceInfo]:
        output = await self._run("idevice_id", "-l")
        devices = []
        for line in output.strip().splitlines():
            udid = line.strip()
            if udid:
                info = await self.get_device_info(udid)
                if info:
                    devices.append(info)
        return devices

    async def get_device_info(self, device_id: str) -> DeviceInfo | None:
        try:
            info_raw = await self._run("ideviceinfo", "-u", device_id)
            info = {}
            for line in info_raw.splitlines():
                if ": " in line:
                    key, val = line.split(": ", 1)
                    info[key.strip()] = val.strip()

            return DeviceInfo(
                id=device_id,
                platform=DevicePlatform.IOS,
                model=info.get("ProductType"),
                os_version=info.get("ProductVersion"),
                arch="arm64",
                is_jailbroken=False,  # detected later via Frida
            )
        except Exception as e:
            logger.warning("Failed to get iOS device info for %s: %s", device_id, e)
            return DeviceInfo(id=device_id, platform=DevicePlatform.IOS)

    async def list_packages(self, device_id: str) -> list[str]:
        output = await self._run("ideviceinstaller", "-u", device_id, "-l")
        packages = []
        for line in output.splitlines():
            if " - " in line and not line.startswith("Total"):
                pkg = line.split(" - ")[0].strip()
                if pkg:
                    packages.append(pkg)
        return packages

    async def pull_app(self, device_id: str, package: str, output_dir: str) -> str | None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ipa_path = out / f"{package}.ipa"
        try:
            await self._run(
                "ideviceinstaller", "-u", device_id,
                "-o", "copy=" + str(out),
                "-a", package,
            )
            if ipa_path.exists():
                return str(ipa_path)
        except Exception as e:
            logger.warning("Failed to pull %s: %s", package, e)
        return None

    async def start_frida_server(self, device_id: str) -> bool:
        try:
            # Start iproxy for Frida port forwarding
            await self.forward_port(device_id, 27042, 27042)

            # SSH in and start frida-server
            ssh_cmd = (
                "ssh -o StrictHostKeyChecking=no -p 2222 root@localhost "
                "'nohup /usr/sbin/frida-server -D > /dev/null 2>&1 &'"
            )
            proc = await asyncio.create_subprocess_shell(
                ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            await asyncio.sleep(1)
            logger.info("frida-server start command sent via SSH")
            return True
        except Exception as e:
            logger.error("Failed to start frida-server on iOS: %s", e)
            return False

    async def forward_port(self, device_id: str, local: int, remote: int) -> bool:
        try:
            # iproxy runs as a background process
            proc = await asyncio.create_subprocess_exec(
                "iproxy", str(local), str(remote), "-u", device_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Give it a moment to bind
            await asyncio.sleep(0.5)
            if proc.returncode is None:  # still running = good
                self._iproxy_proc = proc
                return True
            return False
        except Exception:
            return False

    async def syslog(self, device_id: str, lines: int = 100) -> str:
        return await self._run("idevicesyslog", "-u", device_id, "-n", str(lines))

    async def screenshot(self, device_id: str, output_path: str) -> bool:
        try:
            await self._run("idevicescreenshot", "-u", device_id, output_path)
            return Path(output_path).exists()
        except Exception:
            return False

    async def run_command(self, device_id: str, command: str) -> str:
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p 2222 root@localhost '{command}'"
        proc = await asyncio.create_subprocess_shell(
            ssh_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode(errors="replace")

    async def cleanup(self) -> None:
        if hasattr(self, "_iproxy_proc") and self._iproxy_proc.returncode is None:
            self._iproxy_proc.terminate()

    async def _run(self, *args: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout.decode(errors="replace")
