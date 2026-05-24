"""Function query routes."""

from __future__ import annotations

import mmap
from pathlib import Path
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

    # Surface overlay annotations so the UI can render comments / variable
    # renames inline with the decomp without making a second API call.
    overlay_comments: dict[str, str] = {}
    overlay_var_renames: dict[str, str] = {}
    try:
        from chimera.core.config import ChimeraConfig
        from chimera.core.overlay import ProjectOverlay
        overlay = ProjectOverlay.load(ChimeraConfig().project_dir, model.binary.sha256)
        overlay_comments = overlay.get_comments(address)
        overlay_var_renames = overlay.get_variable_renames(address)
    except Exception:
        # Annotations are best-effort — never block a function read.
        pass

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
        "annotations": {
            "comments": overlay_comments,
            "variable_renames": overlay_var_renames,
        },
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


@router.get("/bytes")
async def get_bytes(
    project_id: str,
    offset: int = Query(0, ge=0),
    length: int = Query(256, ge=1, le=65536),
) -> dict:
    """Return a byte slice as a hex string.

    Uses mmap so multi-MB binaries don't load fully into RAM. Clamps the
    requested range to the file's actual size.

    The stored project path is resolved against the configured allow-roots
    (cache_dir + project_dir + the upload staging dir + CHIMERA_DATA_DIR if
    set) so a malformed project entry cannot trick the endpoint into reading
    arbitrary files via symlink or traversal.
    """
    import os
    from chimera.api.routes.projects import _store
    from chimera.core.config import ChimeraConfig

    project = await _store.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    raw_path = project.get("path", "")
    try:
        path = Path(raw_path).resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(status_code=404, detail="Binary file missing")

    cfg = ChimeraConfig()
    allow_roots: list[Path] = []
    for root in (cfg.cache_dir, cfg.project_dir):
        try:
            allow_roots.append(Path(root).resolve())
        except OSError:
            pass
    for env_var in ("CHIMERA_DATA_DIR", "CHIMERA_UPLOAD_DIR"):
        v = os.environ.get(env_var)
        if v:
            try:
                allow_roots.append(Path(v).resolve())
            except OSError:
                pass
    # The upload route writes here by default (~/.chimera/uploads). Without it
    # the bytes endpoint 403s on every project created through /api/projects/upload.
    try:
        from chimera.api.routes.uploads import _staging_dir
        allow_roots.append(_staging_dir().resolve())
    except Exception:
        pass
    # /data is the conventional read-only mount inside the container.
    if Path("/data").exists():
        allow_roots.append(Path("/data").resolve())

    if allow_roots and not any(
        path == root or root in path.parents for root in allow_roots
    ):
        raise HTTPException(status_code=403, detail="Path outside allowed roots")

    size = path.stat().st_size
    if size == 0 or offset >= size:
        return {"offset": offset, "length": 0, "hex": "", "total_size": size}
    end = min(offset + length, size)
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        chunk = bytes(mm[offset:end])
    return {
        "offset": offset,
        "length": len(chunk),
        "hex": chunk.hex(),
        "total_size": size,
    }
