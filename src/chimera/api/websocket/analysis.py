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
_subscribers: dict[str, list[WebSocket]] = {}


def update_progress(project_id: str, phase: str, detail: str, percent: int):
    _progress[project_id] = {
        "project_id": project_id,
        "phase": phase,
        "detail": detail,
        "percent": percent,
    }
    # Notify subscribers asynchronously
    for ws in _subscribers.get(project_id, []):
        try:
            asyncio.create_task(ws.send_json(_progress[project_id]))
        except Exception:
            pass


@router.websocket("/ws/analysis/{project_id}")
async def analysis_ws(websocket: WebSocket, project_id: str):
    await websocket.accept()
    if project_id not in _subscribers:
        _subscribers[project_id] = []
    _subscribers[project_id].append(websocket)

    try:
        # Send current progress if available
        if project_id in _progress:
            await websocket.send_json(_progress[project_id])

        # Keep connection alive, listen for client messages
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _subscribers.get(project_id, []):
            _subscribers[project_id].remove(websocket)
