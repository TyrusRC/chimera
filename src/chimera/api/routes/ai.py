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
    batch_rename_prompt,
    comment_prompt,
    default_client,
    explain_prompt,
    parse_rename_json,
    refine_decomp_prompt,
    rename_prompt,
    strip_fence,
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


class RefineDecompRequest(BaseModel):
    address: str
    backend: str = "ghidra"        # refine targets the heavy decomp by default
    max_tokens: int = 2048


class BatchRenameRequest(BaseModel):
    max_functions: int = 50
    min_confidence: float = 0.7
    backend: str = "r2"
    apply: bool = False
    skip_already_renamed: bool = True
    max_tokens: int = 160
    # Adversarial verification gate. On by default so the HTTP path matches
    # the CLI: a second model pass must accept a name before --apply commits
    # it. Set false only for trusted, non-adversarial inputs.
    verify: bool = True


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


@router.post("/refine_decomp")
async def refine_decomp(project_id: str, req: RefineDecompRequest) -> dict:
    """LLM4Decompile-V2-style refinement of decompiler output.

    Takes raw Ghidra (or r2) pseudo-C and returns a cleaner version with
    placeholders renamed and obvious control flow tightened. Strictly
    semantic-preserving by prompt contract.
    """
    client = _client_or_503()
    decomp, name, addr = await _resolve_decomp(project_id, req.address, req.backend)
    sys_p, user_p = refine_decomp_prompt(decomp, function_name=name, address=addr)
    try:
        text = await asyncio.to_thread(
            client.complete, sys_p, user_p, max_tokens=req.max_tokens,
        )
    except AIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    # Strip fences if the model wrapped its answer
    refined = strip_fence(text)
    return {
        "address": addr,
        "name": name,
        "refined": refined,
        "original_lines": decomp.count("\n") + 1,
        "refined_lines": refined.count("\n") + 1,
        "model": client.model,
    }


@router.post("/batch_rename")
async def batch_rename(project_id: str, req: BatchRenameRequest) -> dict:
    """SymGen-style batch generative function naming with callgraph context.

    Iterates the project's functions, calls the LLM with caller/callee
    neighbours as context, and optionally writes high-confidence names
    to the overlay. Conservative defaults: confidence threshold 0.7,
    apply=false (preview-only).
    """
    from chimera.api.routes.projects import _store
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay

    client = _client_or_503()
    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]
    overlay = ProjectOverlay.load(ChimeraConfig().project_dir, model.binary.sha256)

    candidates = _select_candidates(model, overlay, req)
    results = await _run_batch_rename(client, model, overlay, candidates, req, project_id)
    return {
        "total_considered": len(candidates),
        "min_confidence": req.min_confidence,
        "applied": sum(1 for r in results if r.get("applied")),
        "suggestions": results,
        "model": client.model,
    }


def _select_candidates(model, overlay, req: BatchRenameRequest) -> list:
    """Pick the next N best functions to ask the LLM to rename.

    Heuristic: stripped-looking names first (FUN_, sub_, fn_, j_), highest
    call-degree first (more callers = more leverage when renamed). Skip
    functions the analyst already renamed in the overlay when the flag is
    set — preserves analyst authority over the model.
    """
    placeholder_prefixes = ("fun_", "sub_", "fn_", "func_", "loc_", "j_")
    out = []
    for f in model.functions:
        name = (f.name or "").lower()
        is_stripped = any(name.startswith(p) for p in placeholder_prefixes) or not name
        if not is_stripped:
            continue
        if req.skip_already_renamed and f.address in overlay.function_names:
            continue
        if not f.decompiled and not (f.disassembly and len(f.disassembly) > 4):
            # Trivial stubs (imports, jumps) won't yield useful names.
            continue
        out.append(f)
    # Highest in-degree first (most leverage from a good rename).
    out.sort(key=lambda f: -len(model.get_callers(f.address) or []))
    return out[: req.max_functions]


async def _run_batch_rename(client, model, overlay, candidates, req, project_id):
    from chimera.api.routes.decomp import decompile as _decomp

    results = []
    for f in candidates:
        # Use cached decomp when present (cheap); only fall back to the
        # live /decomp endpoint when the function has no cached body —
        # avoids paying for a fresh r2 invocation per candidate.
        decomp_text = f.decompiled or ""
        if not decomp_text.strip():
            try:
                payload = await _decomp(
                    project_id=project_id, address=f.address, backend=req.backend,
                )
                decomp_text = (payload["backends"].get(req.backend) or {}).get("code", "") or ""
            except Exception:
                decomp_text = ""
        if not decomp_text.strip():
            continue
        # get_callers/get_callees return FunctionInfo objects, not addresses.
        callers = [c.name for c in (model.get_callers(f.address) or []) if c.name][:6]
        callees = [c.name for c in (model.get_callees(f.address) or []) if c.name][:6]
        sys_p, user_p = batch_rename_prompt(
            decomp_text, current_name=f.name, callers=callers, callees=callees,
        )
        try:
            raw = await asyncio.to_thread(
                client.complete, sys_p, user_p, max_tokens=req.max_tokens,
            )
        except AIError as exc:
            logger.warning("batch_rename: model call failed for %s: %s", f.address, exc)
            continue
        parsed = parse_rename_json(raw)
        if not parsed:
            continue
        entry = {
            "address": f.address,
            "current_name": f.name,
            "suggested_name": parsed["name"],
            "confidence": parsed["confidence"],
            "applied": False,
        }
        if req.apply and parsed["confidence"] >= req.min_confidence:
            verified = True
            if getattr(req, "verify", True):
                # Fail-closed: a second model pass must accept the name before
                # it's written to the overlay. Any verifier error → not applied.
                from chimera.ai import verify_rename
                try:
                    vr = await asyncio.to_thread(
                        verify_rename, decomp_text, parsed["name"],
                        callers, callees, client=client,
                    )
                    verified = bool(vr.accepted)
                    entry["verified"] = verified
                    if vr.reason:
                        entry["verify_reason"] = vr.reason
                except Exception as exc:  # noqa: BLE001 — never crash the batch
                    logger.warning("verify failed for %s: %s", f.address, exc)
                    verified = False
                    entry["verified"] = False
            if verified:
                overlay.rename_function(f.address, parsed["name"])
                f.name = parsed["name"]
                entry["applied"] = True
        results.append(entry)
    if req.apply:
        overlay.save()
    return results


