"""Process-singleton manager for live Frida sessions used by the Web UI."""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# REPL bootstrap script — loaded into every session so /exec can call
# rpc.exports.eval(code).
_REPL_PATH = Path(__file__).parent.parent / "frida_scripts" / "_repl.js"


@dataclass
class FridaSessionRecord:
    id: str
    device_id: Optional[str]
    target: str          # package name (attach) or package name (spawn)
    mode: str            # "attach" | "spawn"
    pid: Optional[int] = None
    _device: Any = None          # frida.core.Device
    _session: Any = None         # frida.core.Session
    _repl_script: Any = None     # the bootstrap script (rpc.exports.eval)
    _queue: asyncio.Queue = field(default_factory=asyncio.Queue)


class FridaSessionManager:
    """Owns all open Frida sessions for the running API process."""

    def __init__(self) -> None:
        self._sessions: dict[str, FridaSessionRecord] = {}
        self._lock = asyncio.Lock()

    # -- frida shims (overridden in tests via monkeypatch) ---------------

    def _get_device_real(self, device_id: Optional[str]):
        import frida
        if device_id:
            return frida.get_device(device_id)
        return frida.get_usb_device(timeout=5)

    # -- public API ------------------------------------------------------

    def list_session_ids(self) -> list[str]:
        return list(self._sessions.keys())

    def get(self, session_id: str) -> Optional[FridaSessionRecord]:
        return self._sessions.get(session_id)

    def subscribe(self, session_id: str) -> asyncio.Queue:
        """Return the live message queue for a session.

        Subscribers consume by `await queue.get()`. The queue is shared by all
        WS subscribers for this session; if you need fanout, drain into a copy.
        """
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)
        return rec._queue

    async def create_session(self, device_id: Optional[str], target: str, mode: str) -> str:
        if mode not in ("attach", "spawn"):
            raise ValueError(f"mode must be 'attach' or 'spawn', got {mode!r}")

        async with self._lock:
            device = self._get_device_real(device_id)
            pid: Optional[int] = None
            if mode == "spawn":
                pid = device.spawn([target])
                session = device.attach(pid)
            else:
                session = device.attach(target)

            sid = uuid.uuid4().hex
            rec = FridaSessionRecord(
                id=sid,
                device_id=device_id,
                target=target,
                mode=mode,
                pid=pid,
                _device=device,
                _session=session,
            )
            # Bootstrap REPL script
            repl_source = _REPL_PATH.read_text(encoding="utf-8")
            repl_script = session.create_script(repl_source)
            repl_script.on("message", lambda message, data: self._enqueue(rec, message))
            repl_script.load()
            rec._repl_script = repl_script

            if mode == "spawn" and pid is not None:
                device.resume(pid)

            self._sessions[sid] = rec
            logger.info("Frida session %s created (mode=%s target=%s)", sid, mode, target)
            return sid

    async def eval_code(self, session_id: str, code: str) -> str:
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)
        # exports_sync.eval matches rpc.exports.eval in _repl.js
        return rec._repl_script.exports_sync.eval(code)

    async def load_script(self, session_id: str, source: str) -> None:
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)
        script = rec._session.create_script(source)
        script.on("message", lambda message, data: self._enqueue(rec, message))
        script.load()

    async def load_bundled_script(self, session_id: str, script_id: str) -> None:
        from chimera.frida_scripts import read_source
        source = read_source(script_id)
        if source is None:
            raise KeyError(script_id)
        await self.load_script(session_id, source)

    async def close_session(self, session_id: str) -> None:
        rec = self._sessions.pop(session_id, None)
        if rec is None:
            return
        # Unload all scripts the session created (best-effort)
        for script in getattr(rec._session, "created_scripts", []):
            try:
                script.unload()
            except Exception as e:  # pragma: no cover — frida raises various
                logger.debug("unload failed for session %s: %s", session_id, e)
        try:
            rec._session.detach()
        except Exception as e:  # pragma: no cover
            logger.debug("detach failed for session %s: %s", session_id, e)

    # -- internals -------------------------------------------------------

    def _enqueue(self, rec: FridaSessionRecord, message: dict) -> None:
        """Frida fires message callbacks on its own thread; bridge to the
        asyncio queue using put_nowait. If the queue is full or closed, drop.
        """
        try:
            rec._queue.put_nowait(message)
        except Exception as e:  # pragma: no cover
            logger.debug("queue push failed for %s: %s", rec.id, e)


_INSTANCE: Optional[FridaSessionManager] = None


def get_session_manager() -> FridaSessionManager:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = FridaSessionManager()
    return _INSTANCE
