"""WebSocket route streaming live Frida session messages to the Web UI."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from chimera.api.frida_session_manager import get_session_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/frida/{session_id}")
async def frida_ws(websocket: WebSocket, session_id: str):
    mgr = get_session_manager()
    if mgr.get(session_id) is None:
        await websocket.close(code=1008, reason="unknown_session")
        return

    await websocket.accept()
    queue = mgr.subscribe(session_id)

    async def drain():
        while True:
            msg = await queue.get()
            try:
                await websocket.send_json(msg)
            except Exception:
                logger.debug("drain ended for session %s", session_id, exc_info=True)
                return

    drain_task = asyncio.create_task(drain())
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        drain_task.cancel()
        mgr.unsubscribe(session_id, queue)
