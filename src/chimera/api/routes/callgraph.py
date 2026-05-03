"""Call graph route."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/projects/{project_id}", tags=["callgraph"])


@router.get("/callgraph/{address}")
async def get_callgraph(project_id: str, address: str, depth: int = Query(2, ge=1, le=10)) -> dict:
    from chimera.api.routes.projects import _store

    p = await _store.get(project_id)
    if not p or "model" not in p:
        raise HTTPException(status_code=404, detail="Project not found")
    model = p["model"]
    nodes, edges = [], []
    visited: set[str] = set()

    def walk(addr: str, d: int) -> None:
        if addr in visited or d > depth:
            return
        visited.add(addr)
        func = model.get_function(addr)
        if not func:
            return
        nodes.append(
            {
                "id": addr,
                "name": func.name,
                "classification": func.classification,
                "layer": func.layer,
            }
        )
        for callee in model.get_callees(addr):
            edges.append({"source": addr, "target": callee.address, "type": "calls"})
            walk(callee.address, d + 1)
        for caller in model.get_callers(addr):
            edges.append({"source": caller.address, "target": addr, "type": "calls"})
            if d < 1:
                walk(caller.address, d + 1)

    walk(address, 0)
    return {"nodes": nodes, "edges": edges, "center": address}
