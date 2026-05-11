"""REST routes for live Frida sessions used by the Web UI."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.api.frida_session_manager import get_session_manager

router = APIRouter(prefix="/api/frida", tags=["frida"])
logger = logging.getLogger(__name__)


class CreateSessionBody(BaseModel):
    device_id: Optional[str] = None
    target: str
    mode: str  # "attach" | "spawn"


class ExecBody(BaseModel):
    code: str


class LoadBody(BaseModel):
    script_id: Optional[str] = None
    source: Optional[str] = None


@router.get("/scripts")
async def list_scripts():
    from chimera.frida_scripts import list_scripts as _ls
    return {"scripts": [s.to_dict() for s in _ls()]}


@router.get("/sessions")
async def list_sessions():
    mgr = get_session_manager()
    out = []
    for sid in mgr.list_session_ids():
        rec = mgr.get(sid)
        if rec is None:
            continue
        out.append({
            "id": rec.id,
            "device_id": rec.device_id,
            "target": rec.target,
            "mode": rec.mode,
            "pid": rec.pid,
        })
    return {"sessions": out}


@router.post("/sessions")
async def create_session(body: CreateSessionBody):
    if body.mode not in ("attach", "spawn"):
        raise HTTPException(status_code=400, detail="mode must be 'attach' or 'spawn'")
    mgr = get_session_manager()
    try:
        sid = await mgr.create_session(body.device_id, body.target, body.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.warning("frida create_session failed: %s", e)
        raise HTTPException(status_code=502, detail=str(e))
    return {"session_id": sid}


@router.post("/sessions/{session_id}/exec")
async def exec_in_session(session_id: str, body: ExecBody):
    mgr = get_session_manager()
    try:
        result = await mgr.eval_code(session_id, body.code)
    except KeyError:
        raise HTTPException(status_code=404, detail="session not found")
    return {"result": result}


@router.post("/sessions/{session_id}/load")
async def load_in_session(session_id: str, body: LoadBody):
    if (body.script_id is None) == (body.source is None):
        raise HTTPException(status_code=400, detail="provide exactly one of script_id or source")
    mgr = get_session_manager()
    if mgr.get(session_id) is None:
        raise HTTPException(status_code=404, detail="session not found")
    try:
        if body.script_id is not None:
            await mgr.load_bundled_script(session_id, body.script_id)
        else:
            await mgr.load_script(session_id, body.source or "")
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown script_id")
    return {"ok": True}


@router.delete("/sessions/{session_id}")
async def close_session(session_id: str):
    mgr = get_session_manager()
    await mgr.close_session(session_id)
    return {"ok": True}
