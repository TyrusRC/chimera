"""VarBERT variable-name recovery routes.

POST /api/projects/{id}/varbert/rename
   Body: { "address": "0x...", "apply": false }

Pushes recovered names into the overlay's `variable_renames` map when
`apply=true`; otherwise returns a preview. 503 when the `varbert_api`
optional dep isn't installed — caller can map to a "feature unavailable"
UX without inspecting the response body shape.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/projects/{project_id}/varbert", tags=["varbert"])
logger = logging.getLogger(__name__)


class RenameRequest(BaseModel):
    address: str
    backend: str = "ghidra"
    apply: bool = False
    variant: str = "ghidra-O2"


@router.get("/status")
async def status(project_id: str) -> dict:
    """Cheap check — UI gates the VarBERT button on this."""
    from chimera.adapters.varbert_adapter import VarBertAdapter
    adapter = VarBertAdapter()
    return {"available": adapter.is_available(), "variant": "ghidra-O2"}


@router.post("/rename")
async def rename(project_id: str, req: RenameRequest) -> dict:
    from chimera.adapters.varbert_adapter import VarBertAdapter
    from chimera.api.routes.decomp import decompile
    from chimera.api.routes.projects import _store
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay

    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]

    adapter = VarBertAdapter(model_variant=req.variant)
    if not adapter.is_available():
        raise HTTPException(
            status_code=503,
            detail=("VarBERT is not installed. `pip install \"chimera[varbert]\"` "
                    "or `pip install varbert-api` to enable variable-name recovery."),
        )

    # Source the decomp through the live endpoint so analyst renames in
    # the overlay are visible to VarBERT — matches the AI surface.
    payload = await decompile(project_id=project_id, address=req.address, backend=req.backend)
    chosen = payload["backends"].get(req.backend) or {}
    if not chosen.get("ok"):
        raise HTTPException(
            status_code=400,
            detail=f"Decompilation via {req.backend} failed: {chosen.get('error', 'unknown')}",
        )
    code = chosen.get("code") or ""

    renames = adapter.rename_function(code, function_address=req.address)
    applied = 0
    if req.apply and renames:
        overlay = ProjectOverlay.load(ChimeraConfig().project_dir, model.binary.sha256)
        for r in renames:
            overlay.rename_variable(req.address, r.original, r.recovered)
            applied += 1
        overlay.save()

    return {
        "address": req.address,
        "variant": req.variant,
        "renames": [
            {"original": r.original, "recovered": r.recovered, "confidence": r.confidence}
            for r in renames
        ],
        "applied": applied,
    }
