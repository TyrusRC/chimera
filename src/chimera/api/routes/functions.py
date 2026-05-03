"""Function query routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

router = APIRouter(prefix="/api/projects/{project_id}", tags=["functions"])


async def _get_model(project_id: str):
    from chimera.api.routes.projects import _store
    p = await _store.get(project_id)
    if not p or "model" not in p:
        raise HTTPException(status_code=404, detail="Project not found or not analyzed")
    return p["model"]


@router.get("/functions")
async def list_functions(
    project_id: str,
    search: Optional[str] = None,
    classification: Optional[str] = None,
    layer: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    model = await _get_model(project_id)
    funcs = model.functions

    if search:
        search_lower = search.lower()
        funcs = [f for f in funcs if search_lower in f.name.lower() or search_lower in f.address.lower()]
    if classification:
        funcs = [f for f in funcs if f.classification == classification]
    if layer:
        funcs = [f for f in funcs if f.layer == layer]

    total = len(funcs)
    funcs = funcs[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "functions": [
            {
                "address": f.address,
                "name": f.name,
                "original_name": f.original_name,
                "language": f.language,
                "classification": f.classification,
                "layer": f.layer,
                "source_backend": f.source_backend,
                "has_decompiled": f.decompiled is not None,
            }
            for f in funcs
        ],
    }


@router.get("/functions/{address}")
async def get_function(project_id: str, address: str) -> dict:
    model = await _get_model(project_id)
    func = model.get_function(address)
    if not func:
        raise HTTPException(status_code=404, detail=f"Function {address} not found")

    callees = model.get_callees(address)
    callers = model.get_callers(address)

    return {
        "address": func.address,
        "name": func.name,
        "original_name": func.original_name,
        "language": func.language,
        "classification": func.classification,
        "layer": func.layer,
        "source_backend": func.source_backend,
        "decompiled": func.decompiled,
        "signature": func.signature,
        "callees": [{"address": c.address, "name": c.name} for c in callees],
        "callers": [{"address": c.address, "name": c.name} for c in callers],
    }


@router.get("/functions/{address}/disassembly")
async def get_disassembly(project_id: str, address: str) -> dict:
    """Return disassembly instructions for a function.

    Falls back to stub data when the backend has not produced raw
    disassembly (e.g. only decompiled source is available).
    """
    model = await _get_model(project_id)
    func = model.get_function(address)
    if not func:
        raise HTTPException(status_code=404, detail=f"Function {address} not found")

    # If the model stores disassembly per-function, use it
    instructions = getattr(func, "disassembly", None) or []
    return {"address": address, "name": func.name, "instructions": instructions}
