"""AI-assisted analyst endpoints — explain, suggest_name, suggest_comment.

All three operate on the *current* live decompilation (r2 by default, Ghidra
when cached), so analyst renames already pushed into the overlay are visible
to the LLM. This matches the rest of the analyst surface: what you see in
the UI is what gets sent.

The endpoints return 503 with a clear message when ANTHROPIC_API_KEY is
unset — chimera ships AI as opt-in, not opt-out.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from chimera.ai import (
    AIError,
    AINotConfigured,
    comment_prompt,
    default_client,
    explain_prompt,
    rename_prompt,
)

router = APIRouter(prefix="/api/projects/{project_id}/ai", tags=["ai"])
logger = logging.getLogger(__name__)


class ExplainRequest(BaseModel):
    address: str
    backend: str = "r2"        # r2 | ghidra
    max_tokens: int = 800


class RenameRequest(BaseModel):
    address: str
    backend: str = "r2"
    max_tokens: int = 80


class CommentRequest(BaseModel):
    address: str
    line: int = 0
    backend: str = "r2"
    max_tokens: int = 200


async def _resolve_decomp(project_id: str, address: str, backend: str) -> tuple[str, str, str]:
    """Return (decomp_code, function_name, address) for the live function.

    Reuses `decomp.decompile` so analyst renames in the overlay surface to
    the LLM. The duplication overhead here would be a re-implementation of
    the post-processor — not worth the speed.
    """
    from chimera.api.routes.decomp import decompile

    payload = await decompile(project_id=project_id, address=address, backend=backend)
    chosen = payload["backends"].get(backend) or {}
    if not chosen.get("ok"):
        raise HTTPException(
            status_code=400,
            detail=f"Decompilation via {backend} failed: {chosen.get('error', 'unknown')}",
        )
    return chosen["code"], payload.get("name") or "", payload.get("address") or address


def _client_or_503():
    try:
        return default_client()
    except AINotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/status")
async def status(project_id: str) -> dict:
    """Cheap check the Web UI can hit before showing AI buttons."""
    try:
        client = default_client()
        return {"available": True, "model": client.model}
    except AINotConfigured:
        return {"available": False, "model": None}


@router.post("/explain")
async def explain(project_id: str, req: ExplainRequest) -> dict:
    client = _client_or_503()
    decomp, name, addr = await _resolve_decomp(project_id, req.address, req.backend)
    sys_p, user_p = explain_prompt(decomp, function_name=name, address=addr)
    try:
        text = await asyncio.to_thread(client.complete, sys_p, user_p, max_tokens=req.max_tokens)
    except AIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"address": addr, "name": name, "explanation": text, "model": client.model}


@router.post("/rename")
async def suggest_rename(project_id: str, req: RenameRequest) -> dict:
    client = _client_or_503()
    decomp, name, addr = await _resolve_decomp(project_id, req.address, req.backend)
    sys_p, user_p = rename_prompt(decomp, current_name=name)
    try:
        text = await asyncio.to_thread(client.complete, sys_p, user_p, max_tokens=req.max_tokens)
    except AIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    suggested = text.strip().splitlines()[0].strip().strip("`'\"") if text else ""
    return {"address": addr, "current_name": name, "suggested_name": suggested, "model": client.model}


@router.post("/comment")
async def suggest_comment(project_id: str, req: CommentRequest) -> dict:
    client = _client_or_503()
    decomp, name, addr = await _resolve_decomp(project_id, req.address, req.backend)
    sys_p, user_p = comment_prompt(decomp, line=req.line)
    try:
        text = await asyncio.to_thread(client.complete, sys_p, user_p, max_tokens=req.max_tokens)
    except AIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "address": addr, "name": name, "line": req.line,
        "comment": text.strip(),
        "model": client.model,
    }
