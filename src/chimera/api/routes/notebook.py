"""Notebook — narrative analyst findings with evidence links.

A Sidekick-style scratch pad: each note has a title, freeform body, tags,
and a list of evidence items pointing back at concrete addresses (and
optionally decompiler line numbers). Notes live in the same `overlay.json`
as renames and comments, so they travel with the project and round-trip
through the existing export/import.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.core.config import ChimeraConfig
from chimera.core.overlay import ProjectOverlay

router = APIRouter(prefix="/api/projects/{project_id}/notes", tags=["notebook"])
logger = logging.getLogger(__name__)


class EvidenceItem(BaseModel):
    address: str
    line: int = 0


class CreateNoteRequest(BaseModel):
    title: str
    body: str = ""
    tags: Optional[list[str]] = None
    evidence: Optional[list[EvidenceItem]] = None


class UpdateNoteRequest(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    tags: Optional[list[str]] = None
    evidence: Optional[list[EvidenceItem]] = None


async def _load_overlay(project_id: str) -> tuple[ProjectOverlay, str]:
    """Resolve the project's overlay; 404 if the project isn't analyzed yet.

    Same pattern as overlay_io._load — we deliberately don't duplicate the
    project store lookup logic.
    """
    from chimera.api.routes.projects import _store
    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]
    sha = model.binary.sha256
    overlay = ProjectOverlay.load(ChimeraConfig().project_dir, sha)
    return overlay, sha


@router.get("")
async def list_notes(project_id: str, tag: Optional[str] = None) -> dict:
    overlay, sha = await _load_overlay(project_id)
    entries = overlay.list_notes(tag=tag)
    return {
        "project_id": project_id,
        "sha256": sha,
        "count": len(entries),
        "notes": entries,
    }


@router.post("")
async def create_note(project_id: str, req: CreateNoteRequest) -> dict:
    overlay, _sha = await _load_overlay(project_id)
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="title is required")
    evidence = [e.model_dump() for e in (req.evidence or [])]
    note_id = overlay.add_note(
        title=req.title,
        body=req.body,
        tags=req.tags,
        evidence=evidence,
    )
    overlay.save()
    return {"ok": True, "id": note_id, "note": overlay.notes[note_id]}


@router.patch("/{note_id}")
async def update_note(project_id: str, note_id: str, req: UpdateNoteRequest) -> dict:
    overlay, _sha = await _load_overlay(project_id)
    fields: dict = {}
    if req.title is not None:
        fields["title"] = req.title
    if req.body is not None:
        fields["body"] = req.body
    if req.tags is not None:
        fields["tags"] = req.tags
    if req.evidence is not None:
        fields["evidence"] = [e.model_dump() for e in req.evidence]
    ok = overlay.update_note(note_id, **fields)
    if not ok:
        raise HTTPException(status_code=404, detail=f"no such note: {note_id}")
    overlay.save()
    return {"ok": True, "id": note_id, "note": overlay.notes[note_id]}


@router.delete("/{note_id}")
async def delete_note(project_id: str, note_id: str) -> dict:
    overlay, _sha = await _load_overlay(project_id)
    removed = overlay.remove_note(note_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"no such note: {note_id}")
    overlay.save()
    return {"ok": True, "id": note_id}
