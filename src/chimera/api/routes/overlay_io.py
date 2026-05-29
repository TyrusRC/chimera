"""Overlay export/import — portable analyst annotations.

Lets analysts share renames/comments/types across machines or between
team members. The exported JSON includes the binary sha256 so an import
into a project against a different binary surfaces a warning rather than
silently dropping addresses.

Schema: chimera-overlay-export/1 (separate from the on-disk overlay
schema to allow either side to evolve without breaking the other).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.core.config import ChimeraConfig
from chimera.core.overlay import ProjectOverlay

router = APIRouter(prefix="/api/projects/{project_id}/overlay", tags=["overlay"])
logger = logging.getLogger(__name__)


EXPORT_SCHEMA = "chimera-overlay-export/1"


class ImportRequest(BaseModel):
    payload: dict
    mode: str = "merge"  # "merge" | "replace"


async def _load(project_id: str) -> tuple[ProjectOverlay, "UnifiedProgramModel", str]:
    from chimera.api.routes.projects import _store
    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]
    sha = model.binary.sha256
    overlay = ProjectOverlay.load(ChimeraConfig().project_dir, sha)
    return overlay, model, sha


@router.get("/export")
async def export_overlay(project_id: str) -> dict:
    overlay, _model, sha = await _load(project_id)
    return {
        "schema": EXPORT_SCHEMA,
        "sha256": sha,
        "function_names": overlay.function_names,
        "variable_renames": overlay.variable_renames,
        "comments": overlay.comments,
        "function_types": overlay.function_types,
        "user_classifications": overlay.user_classifications,
    }


@router.post("/import")
async def import_overlay(project_id: str, req: ImportRequest) -> dict:
    overlay, model, sha = await _load(project_id)
    payload = req.payload or {}
    incoming_sha = payload.get("sha256") or ""
    warnings: list[str] = []
    if incoming_sha and incoming_sha != sha:
        warnings.append(
            f"overlay was exported from a different binary "
            f"(sha={incoming_sha[:12]}… vs current {sha[:12]}…); "
            "addresses may not line up"
        )

    if req.mode not in ("merge", "replace"):
        raise HTTPException(status_code=400, detail=f"unknown mode: {req.mode!r}")

    if req.mode == "replace":
        overlay.function_names.clear()
        overlay.variable_renames.clear()
        overlay.comments.clear()
        overlay.function_types.clear()
        overlay.user_classifications.clear()

    overlay.function_names.update(payload.get("function_names") or {})
    for addr, vmap in (payload.get("variable_renames") or {}).items():
        overlay.variable_renames.setdefault(addr, {}).update(vmap)
    for addr, cmap in (payload.get("comments") or {}).items():
        overlay.comments.setdefault(addr, {}).update(cmap)
    overlay.function_types.update(payload.get("function_types") or {})
    overlay.user_classifications.update(payload.get("user_classifications") or {})

    # Sync the live model so subsequent reads see imported renames.
    for addr, new_name in overlay.function_names.items():
        f = model.get_function(addr)
        if f is not None:
            f.name = new_name
    overlay.save()
    return {
        "ok": True,
        "mode": req.mode,
        "warnings": warnings,
        "counts": {
            "function_names": len(overlay.function_names),
            "comments": len(overlay.comments),
            "function_types": len(overlay.function_types),
            "user_classifications": len(overlay.user_classifications),
        },
    }
