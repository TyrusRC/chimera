"""Analyst annotations — function rename, comments, types.

Every mutation:
  1. Updates the live `UnifiedProgramModel` in the project store so the
     change is visible immediately to subsequent API reads.
  2. Persists to `<project_dir>/<sha>/overlay.json` so it survives restart.

The same data is what the CLI surface and any future TUI editor should
read/write, so the storage location (`overlay.json`) is intentionally
package-agnostic — not tied to FastAPI.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.core.config import ChimeraConfig
from chimera.core.overlay import ProjectOverlay

router = APIRouter(prefix="/api/projects/{project_id}/annotations", tags=["annotations"])
logger = logging.getLogger(__name__)


# ---------- request schemas ------------------------------------------------


class RenameRequest(BaseModel):
    kind: str            # "function" | "variable"
    address: str         # function address (hex string)
    new_name: str
    original: Optional[str] = None   # only meaningful for kind=variable


class CommentRequest(BaseModel):
    address: str
    text: str
    line: Optional[int] = None       # 0 = function header / global comment


class TypeRequest(BaseModel):
    address: str
    signature: str       # free-form C signature


class ClassificationRequest(BaseModel):
    address: str
    classification: str


# ---------- helpers --------------------------------------------------------


async def _load_overlay_and_model(project_id: str) -> tuple[ProjectOverlay, "UnifiedProgramModel", str]:
    """Resolve sha from the in-memory project and return (overlay, model, sha).

    Raises 404 if the project isn't analyzed yet. Read state lives in
    `projects._store`; we deliberately do not duplicate that authority here.
    """
    from chimera.api.routes.projects import _store
    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]
    sha = model.binary.sha256
    cfg = ChimeraConfig()
    overlay = ProjectOverlay.load(cfg.project_dir, sha)
    return overlay, model, sha


def _apply_overlay_to_store_model(overlay: ProjectOverlay, model) -> int:
    """Push the on-disk overlay back into the live model in the store."""
    return overlay.apply_to_model(model)


# ---------- routes ---------------------------------------------------------


@router.get("")
async def list_annotations(project_id: str) -> dict:
    overlay, _model, sha = await _load_overlay_and_model(project_id)
    return {
        "project_id": project_id,
        "sha256": sha,
        "function_names": overlay.function_names,
        "variable_renames": overlay.variable_renames,
        "comments": overlay.comments,
        "function_types": overlay.function_types,
        "user_classifications": overlay.user_classifications,
    }


@router.post("/rename")
async def rename(project_id: str, req: RenameRequest) -> dict:
    overlay, model, _sha = await _load_overlay_and_model(project_id)
    if req.kind == "function":
        overlay.rename_function(req.address, req.new_name)
        # Update the live model so the next /functions read sees it.
        f = model.get_function(req.address)
        if f is not None:
            f.name = req.new_name
    elif req.kind == "variable":
        if not req.original:
            raise HTTPException(status_code=400, detail="variable rename requires `original`")
        overlay.rename_variable(req.address, req.original, req.new_name)
    else:
        raise HTTPException(status_code=400, detail=f"unknown rename kind: {req.kind!r}")
    overlay.save()
    return {"ok": True, "kind": req.kind, "address": req.address, "new_name": req.new_name}


@router.post("/comment")
async def add_comment(project_id: str, req: CommentRequest) -> dict:
    overlay, _model, _sha = await _load_overlay_and_model(project_id)
    line = req.line if req.line is not None else 0
    overlay.add_comment(req.address, line, req.text)
    overlay.save()
    return {"ok": True, "address": req.address, "line": line}


@router.post("/type")
async def set_type(project_id: str, req: TypeRequest) -> dict:
    overlay, model, _sha = await _load_overlay_and_model(project_id)
    overlay.set_function_type(req.address, req.signature)
    f = model.get_function(req.address)
    if f is not None:
        f.signature = req.signature
    overlay.save()
    return {"ok": True, "address": req.address, "signature": req.signature}


@router.post("/classify")
async def classify(project_id: str, req: ClassificationRequest) -> dict:
    overlay, model, _sha = await _load_overlay_and_model(project_id)
    overlay.set_classification(req.address, req.classification)
    f = model.get_function(req.address)
    if f is not None:
        f.classification = req.classification
    overlay.save()
    return {"ok": True, "address": req.address, "classification": req.classification}


@router.delete("/rename/{address}")
async def delete_rename(project_id: str, address: str) -> dict:
    overlay, model, _sha = await _load_overlay_and_model(project_id)
    removed = overlay.delete_function_name(address)
    if removed:
        overlay.save()
        # Restore the original backend-emitted name in the live model.
        f = model.get_function(address)
        if f is not None:
            f.name = f.original_name
    return {"ok": removed, "address": address}
