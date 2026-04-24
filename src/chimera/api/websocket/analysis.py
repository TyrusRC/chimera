"""Analysis progress WebSocket — streams analysis status to frontend."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()
logger = logging.getLogger(__name__)

# Global progress store — updated by analysis pipeline
_progress: dict[str, dict] = {}
_subscribers: dict[str, list] = {}


async def broadcast_progress(project_id: str) -> None:
    """Send current progress to every subscriber. Drops subscribers that fail to receive."""
    subs = _subscribers.get(project_id, [])
    if not subs:
        return
    payload = _progress.get(project_id, {})
    alive = []
    for ws in subs:
        try:
            await ws.send_json(payload)
            alive.append(ws)
        except Exception as exc:
            logger.debug("dropping closed websocket for %s: %s", project_id, exc)
    _subscribers[project_id] = alive


def update_progress(project_id: str, phase: str, detail: str, percent: int) -> None:
    """Record progress and schedule a broadcast to subscribers."""
    _progress[project_id] = {
        "project_id": project_id,
        "phase": phase,
        "detail": detail,
        "percent": percent,
    }
    # Schedule awaited broadcast on the running loop. If we're not in a loop
    # (unusual — this is called from within request handlers), just skip.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(broadcast_progress(project_id))


@router.websocket("/ws/analysis/{project_id}")
async def analysis_ws(websocket: WebSocket, project_id: str):
    await websocket.accept()
    if project_id not in _subscribers:
        _subscribers[project_id] = []
    _subscribers[project_id].append(websocket)

    try:
        if project_id in _progress:
            await websocket.send_json(_progress[project_id])
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _subscribers.get(project_id, []):
            _subscribers[project_id].remove(websocket)
