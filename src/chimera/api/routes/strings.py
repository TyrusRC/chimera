"""String query routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

router = APIRouter(prefix="/api/projects/{project_id}", tags=["strings"])


@router.get("/strings")
async def list_strings(
    project_id: str,
    search: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
) -> dict:
    from chimera.api.routes.projects import _projects
    p = _projects.get(project_id)
    if not p or "model" not in p:
        raise HTTPException(status_code=404, detail="Project not found")
    model = p["model"]

    if search:
        strings = model.get_strings(pattern=search)
    else:
        strings = model.get_strings()

    total = len(strings)
    strings = strings[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "strings": [
            {
                "address": s.address,
                "value": s.value,
                "section": s.section,
                "decrypted_from": s.decrypted_from,
            }
            for s in strings
        ],
    }
