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

# Per-subscriber queue cap. When a subscriber falls behind, oldest message is
# dropped. Prevents unbounded growth from a slow or disappeared WS client.
_QUEUE_MAXSIZE = 1024


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
    _subscribers: list = field(default_factory=list)  # list[asyncio.Queue]
    _loop: Any = None  # asyncio loop captured at create_session time
    _scripts: list = field(default_factory=list)


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
        """Register a new subscriber and return its dedicated bounded queue.

        Each call returns a fresh per-subscriber queue. Frida messages are
        fanned out to every subscribed queue, so a second WS client does not
        steal messages from the first. The queue is bounded; if a subscriber
        falls behind, the oldest message is dropped to make room.
        """
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        rec._subscribers.append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        """Remove a previously-subscribed queue from the fanout list.

        Safe to call with an unknown session_id or a queue that is not (or no
        longer) registered. Once unsubscribed, no further messages are
        delivered to ``queue``.
        """
        rec = self._sessions.get(session_id)
        if rec is None:
            return
        try:
            rec._subscribers.remove(queue)
        except ValueError:
            pass

    async def create_session(self, device_id: Optional[str], target: str, mode: str) -> str:
        if mode not in ("attach", "spawn"):
            raise ValueError(f"mode must be 'attach' or 'spawn', got {mode!r}")

        loop = asyncio.get_running_loop()
        sid = uuid.uuid4().hex

        def _do() -> FridaSessionRecord:
            device = self._get_device_real(device_id)
            pid: Optional[int] = None
            if mode == "spawn":
                pid = device.spawn([target])
                session = device.attach(pid)
            else:
                session = device.attach(target)

            rec = FridaSessionRecord(
                id=sid,
                device_id=device_id,
                target=target,
                mode=mode,
                pid=pid,
                _device=device,
                _session=session,
                _loop=loop,
            )
            # Bootstrap REPL script
            repl_source = _REPL_PATH.read_text(encoding="utf-8")
            repl_script = session.create_script(repl_source)
            repl_script.on("message", lambda message, data: self._enqueue(rec, message))
            repl_script.load()
            rec._repl_script = repl_script
            rec._scripts.append(repl_script)

            if mode == "spawn" and pid is not None:
                device.resume(pid)
            return rec

        rec = await asyncio.to_thread(_do)
        async with self._lock:
            self._sessions[sid] = rec
        logger.info("Frida session %s created (mode=%s target=%s)", sid, mode, target)
        return sid

    async def eval_code(self, session_id: str, code: str) -> str:
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)
        # exports_sync.eval matches rpc.exports.eval in _repl.js
        return await asyncio.to_thread(rec._repl_script.exports_sync.eval, code)

    async def load_script(self, session_id: str, source: str) -> None:
        rec = self._sessions.get(session_id)
        if rec is None:
            raise KeyError(session_id)

        def _do():
            script = rec._session.create_script(source)
            script.on("message", lambda message, data: self._enqueue(rec, message))
            script.load()
            return script

        script = await asyncio.to_thread(_do)
        rec._scripts.append(script)

    async def load_bundled_script(self, session_id: str, script_id: str) -> None:
        from chimera.frida_scripts import read_source
        source = read_source(script_id)
        if source is None:
            raise KeyError(script_id)
        await self.load_script(session_id, source)

    async def close_session(self, session_id: str) -> None:
        async with self._lock:
            rec = self._sessions.pop(session_id, None)
        if rec is None:
            return

        def _do():
            for script in rec._scripts:
                try:
                    script.unload()
                except Exception as e:  # pragma: no cover — frida raises various
                    logger.debug("unload failed for session %s: %s", session_id, e)
            try:
                rec._session.detach()
            except Exception as e:  # pragma: no cover
                logger.debug("detach failed for session %s: %s", session_id, e)

        await asyncio.to_thread(_do)

    # -- internals -------------------------------------------------------

    def _enqueue(self, rec: FridaSessionRecord, message: dict) -> None:
        """Fan out a Frida message to every subscriber.

        Frida fires message callbacks on its own thread, so we bridge to the
        asyncio loop via call_soon_threadsafe. Each subscriber has a bounded
        queue; on overflow we drop the oldest message rather than block or
        grow without bound. With zero subscribers this is effectively a no-op.
        """
        loop = rec._loop

        def _deliver(sub: asyncio.Queue, msg: dict) -> None:
            if sub.full():
                try:
                    sub.get_nowait()  # drop oldest
                except asyncio.QueueEmpty:
                    pass
            try:
                sub.put_nowait(msg)
            except Exception as e:  # pragma: no cover — defensive
                logger.debug("subscriber put failed for %s: %s", rec.id, e)

        # Snapshot — list may mutate concurrently as subscribers come and go.
        for sub in list(rec._subscribers):
            if loop is None:
                # No loop captured (test path that didn't go through create_session)
                _deliver(sub, message)
            else:
                try:
                    loop.call_soon_threadsafe(_deliver, sub, message)
                except RuntimeError as e:  # loop closed
                    logger.debug("loop closed for %s: %s", rec.id, e)


_INSTANCE: Optional[FridaSessionManager] = None


def get_session_manager() -> FridaSessionManager:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = FridaSessionManager()
    return _INSTANCE
