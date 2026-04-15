"""Frida adapter — runtime instrumentation for both Android and iOS."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


class FridaSession:
    """Manages a single Frida session attached to an app."""

    def __init__(self, device, session, script=None):
        self._device = device
        self._session = session
        self._script = script
        self._messages: list[dict] = []

    @property
    def messages(self) -> list[dict]:
        return list(self._messages)

    def _on_message(self, message: dict, data: Any) -> None:
        self._messages.append(message)
        if message.get("type") == "send":
            logger.debug("Frida message: %s", message.get("payload"))

    async def load_script(self, source: str) -> None:
        self._script = self._session.create_script(source)
        self._script.on("message", self._on_message)
        self._script.load()

    async def evaluate(self, js_code: str) -> Any:
        if self._script:
            return self._script.exports_sync.rpc_call(js_code) if hasattr(self._script.exports_sync, 'rpc_call') else None
        return None

    async def detach(self) -> None:
        if self._script:
            try:
                self._script.unload()
            except Exception:
                pass
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass


class FridaAdapter(BackendAdapter):
    def __init__(self):
        self._sessions: dict[str, FridaSession] = {}

    def name(self) -> str:
        return "frida"

    def is_available(self) -> bool:
        try:
            import frida
            return True
        except ImportError:
            return False

    def supported_formats(self) -> list[str]:
        return ["apk", "ipa", "elf", "macho"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=256, category=ToolCategory.LIGHT, estimated_seconds=5)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Not used directly — use attach/spawn + load_script instead."""
        return {"error": "Use attach() or spawn() for Frida operations"}

    async def attach(self, package_or_pid: str | int, device_id: str | None = None) -> FridaSession | None:
        try:
            import frida
            if device_id:
                device = frida.get_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            if isinstance(package_or_pid, int):
                session = device.attach(package_or_pid)
            else:
                session = device.attach(package_or_pid)

            frida_session = FridaSession(device, session)
            key = str(package_or_pid)
            self._sessions[key] = frida_session
            logger.info("Attached to %s", package_or_pid)
            return frida_session
        except Exception as e:
            logger.error("Failed to attach: %s", e)
            return None

    async def spawn(self, package: str, device_id: str | None = None,
                    script_source: str | None = None) -> FridaSession | None:
        try:
            import frida
            if device_id:
                device = frida.get_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            pid = device.spawn([package])
            session = device.attach(pid)
            frida_session = FridaSession(device, session)

            if script_source:
                await frida_session.load_script(script_source)

            device.resume(pid)
            self._sessions[package] = frida_session
            logger.info("Spawned %s (PID %d)", package, pid)
            return frida_session
        except Exception as e:
            logger.error("Failed to spawn: %s", e)
            return None

    async def load_script_file(self, session_key: str, script_path: str | Path) -> bool:
        session = self._sessions.get(session_key)
        if not session:
            return False
        source = Path(script_path).read_text()
        await session.load_script(source)
        return True

    async def cleanup(self) -> None:
        for session in self._sessions.values():
            await session.detach()
        self._sessions.clear()
