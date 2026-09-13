"""Android device manager — wraps ADB for device interaction."""

from __future__ import annotations

import asyncio
import logging
import shlex
import shutil
from pathlib import Path

from chimera.device.base import DeviceManager, DeviceInfo, DevicePlatform

logger = logging.getLogger(__name__)


class AdbError(RuntimeError):
    def __init__(self, cmd: str, returncode: int, stderr: str) -> None:
        super().__init__(f"adb {cmd} failed (rc={returncode}): {stderr[-2000:]}")
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


class AndroidDeviceManager(DeviceManager):
    @property
    def name(self) -> str:
        return "android"

    @property
    def is_available(self) -> bool:
        return shutil.which("adb") is not None

    async def connect(self, target: str, *, timeout: float = 10.0) -> bool:
        """Attach a device/emulator reachable over TCP/IP via `adb connect`.

        USB devices and locally-running emulators already show up in
        `adb devices`; this is for a networked ROOT device (adb-over-Wi-Fi) or a
        remote/headless emulator that must be dialled first. A bare host gets the
        default adb port :5555. adb connect exits 0 even on some failures, so
        success is judged from the output text ("connected to ..."), not the
        return code. It also BLOCKS indefinitely on an unreachable target, so the
        call is bounded by `timeout` (a timeout is reported as failure).
        """
        if ":" not in target:
            target = f"{target}:5555"
        try:
            out = await self._adb_argv(["connect", target], timeout=timeout)
        except AdbError as e:
            out = e.stderr  # non-zero exit / timeout still carries the reason
        return "connected to" in out.lower()

    async def disconnect(self, target: str | None = None, *, timeout: float = 10.0) -> bool:
        """`adb disconnect <target>` (or all TCP/IP devices when target is None)."""
        argv = ["disconnect"] + ([target] if target else [])
        try:
            await self._adb_argv(argv, timeout=timeout)
            return True
        except AdbError:
            return False

    async def list_devices(self) -> list[DeviceInfo]:
        output = await self._adb_argv(["devices"])
        devices = []
        for line in output.strip().splitlines()[1:]:  # skip header
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].strip() == "device":
                device_id = parts[0].strip()
                info = await self.get_device_info(device_id)
                if info:
                    devices.append(info)
        return devices

    async def get_device_info(self, device_id: str) -> DeviceInfo | None:
        try:
            model = (await self._adb_device_argv(device_id, ["shell", "getprop", "ro.product.model"])).strip()
            version = (await self._adb_device_argv(device_id, ["shell", "getprop", "ro.build.version.release"])).strip()
            arch = (await self._adb_device_argv(device_id, ["shell", "getprop", "ro.product.cpu.abi"])).strip()

            # Check root
            su_check = await self._adb_device_argv(device_id, ["shell", "su", "-c", "id"])
            is_rooted = "uid=0" in su_check

            return DeviceInfo(
                id=device_id,
                platform=DevicePlatform.ANDROID,
                model=model or None,
                os_version=version or None,
                arch=arch or None,
                is_rooted=is_rooted,
            )
        except Exception as e:
            logger.warning("Failed to get device info for %s: %s", device_id, e)
            return DeviceInfo(id=device_id, platform=DevicePlatform.ANDROID)

    async def list_packages(self, device_id: str) -> list[str]:
        output = await self._adb_device_argv(device_id, ["shell", "pm", "list", "packages"])
        return [line.replace("package:", "").strip()
                for line in output.splitlines() if line.startswith("package:")]

    async def pull_app(self, device_id: str, package: str, output_dir: str) -> list[str] | None:
        output = await self._adb_device_argv(device_id, ["shell", "pm", "path", package])
        paths = [line.replace("package:", "").strip()
                 for line in output.splitlines() if line.startswith("package:")]
        if not paths:
            return None

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        pulled: list[str] = []
        for apk_path in paths:
            local = out / Path(apk_path).name
            await self._adb_device_argv(device_id, ["pull", apk_path, str(local)])
            pulled.append(str(local))
        return pulled or None

    async def start_frida_server(self, device_id: str, server_path: str = "/data/local/tmp/frida-server") -> bool:
        try:
            # Check if already running
            check = await self._adb_device_argv(device_id, ["shell", "su", "-c", "pidof frida-server"])
            if check.strip():
                logger.info("frida-server already running (PID %s)", check.strip())
                return True

            # Start frida-server — quote path in case it contains spaces/metachars
            start_cmd = f"{shlex.quote(server_path)} -D &"
            await self._adb_device_argv(device_id, ["shell", "su", "-c", start_cmd])
            await asyncio.sleep(1)

            # Verify
            check = await self._adb_device_argv(device_id, ["shell", "su", "-c", "pidof frida-server"])
            running = bool(check.strip())
            if running:
                logger.info("frida-server started successfully")
            else:
                logger.warning("frida-server failed to start")
            return running
        except Exception as e:
            logger.error("Failed to start frida-server: %s", e)
            return False

    async def forward_port(self, device_id: str, local: int, remote: int) -> bool:
        try:
            await self._adb_device_argv(device_id, ["forward", f"tcp:{local}", f"tcp:{remote}"])
            return True
        except Exception:
            return False

    async def setup_proxy(self, device_id: str, host: str, port: int) -> bool:
        try:
            await self._adb_device_argv(
                device_id, ["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"]
            )
            return True
        except Exception:
            return False

    async def clear_proxy(self, device_id: str) -> bool:
        try:
            await self._adb_device_argv(device_id, ["shell", "settings", "delete", "global", "http_proxy"])
            return True
        except Exception:
            return False

    async def logcat(self, device_id: str, package: str, lines: int = 100) -> str:
        pid_output = await self._adb_device_argv(device_id, ["shell", "pidof", package])
        pid = pid_output.strip()
        if pid:
            return await self._adb_device_argv(device_id, ["logcat", f"--pid={pid}", "-d", "-t", str(lines)])
        return await self._adb_device_argv(device_id, ["logcat", "-d", "-t", str(lines)])

    async def run_command(self, device_id: str, command: str) -> str:
        return await self._adb_device_argv(device_id, ["shell", command])

    async def is_alive(self, device_id: str) -> bool:
        try:
            await self._adb_device_argv(device_id, ["shell", "echo", "1"])
            return True
        except Exception:
            return False

    async def cleanup(self) -> None:
        pass

    async def _adb_argv(self, argv: list[str], *, timeout: float | None = None) -> str:
        proc = await asyncio.create_subprocess_exec(
            "adb", *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            # `adb connect` blocks forever on an unreachable target — kill the
            # client so the call returns. NOTE: the adb *server* may keep the
            # pending connect; that's harmless and reaped on the next command.
            proc.kill()
            await proc.wait()
            raise AdbError(" ".join(argv), -1, f"timed out after {timeout}s")
        if proc.returncode != 0:
            raise AdbError(
                " ".join(argv), proc.returncode or -1, stderr.decode(errors="replace"),
            )
        return stdout.decode(errors="replace")

    async def _adb_device_argv(self, device_id: str, argv: list[str],
                               *, timeout: float | None = None) -> str:
        return await self._adb_argv(["-s", device_id, *argv], timeout=timeout)
