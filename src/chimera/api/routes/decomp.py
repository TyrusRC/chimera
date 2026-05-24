"""On-demand decompilation routes.

`GET /api/projects/{id}/functions/{addr}/decomp?backend=r2|ghidra|all`
runs the chosen decompiler against the function at `addr`, applies the
post-processor (so DAT_addr → "string", FUN_addr → recovered_name,
iVar1 → typed locals, C++ demangled), then returns the cleaned-up code.

The endpoint is intentionally live — we don't trust a cached decompilation
because the user may have renamed functions / variables since the binary
was analyzed, and the overlay's substitutions should reflect *current*
state.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/projects/{project_id}/functions/{address}", tags=["decomp"])
logger = logging.getLogger(__name__)


async def _resolve(project_id: str, address: str):
    from chimera.api.routes.projects import _store
    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    model = project["model"]
    func = model.get_function(address)
    if not func:
        raise HTTPException(status_code=404, detail=f"Function {address} not found in model")
    binary_path = project.get("path")
    if not binary_path:
        raise HTTPException(status_code=500, detail="Project has no recorded binary path")
    return model, func, binary_path


@router.get("/decomp")
async def decompile(
    project_id: str,
    address: str,
    backend: str = Query("r2", pattern="^(r2|ghidra|all)$"),
) -> dict:
    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay
    from chimera.report.decomp_postprocess import post_process

    model, func, binary_path = await _resolve(project_id, address)
    overlay = ProjectOverlay.load(ChimeraConfig().project_dir, model.binary.sha256)

    backends: dict[str, dict] = {}

    if backend in ("r2", "all"):
        r2 = Radare2Adapter()
        if not r2.is_available():
            backends["r2"] = {"ok": False, "code": "", "lines": 0, "error": "r2 not on PATH"}
        else:
            try:
                # r2pipe blocks; offload to a thread so we don't stall the loop.
                raw = await asyncio.to_thread(
                    _r2_decompile_sync, r2, binary_path, address,
                )
                if raw.get("ok"):
                    pp = post_process(raw["code"], model, address, overlay=overlay)
                    backends["r2"] = {
                        "ok": True, "code": pp.code, "lines": pp.code.count("\n") + 1,
                        "substitutions": pp.substitutions,
                        "inserted_strings": pp.inserted_strings,
                        "inserted_names": pp.inserted_names,
                    }
                else:
                    backends["r2"] = {"ok": False, "code": "", "lines": 0, "error": raw.get("error", "unknown")}
            except Exception as exc:
                logger.exception("r2 decompile failed for %s @ %s", binary_path, address)
                backends["r2"] = {"ok": False, "code": "", "lines": 0, "error": str(exc)}

    if backend in ("ghidra", "all"):
        # Ghidra's headless decompile-per-function is heavy (~30 s warm).
        # Use the cached model decompilation when present, post-process it,
        # and tell the caller why this is "not a live run" so they don't
        # mistake stale output for fresh.
        if func.decompiled:
            pp = post_process(func.decompiled, model, address, overlay=overlay)
            backends["ghidra"] = {
                "ok": True, "code": pp.code, "lines": pp.code.count("\n") + 1,
                "substitutions": pp.substitutions,
                "inserted_strings": pp.inserted_strings,
                "inserted_names": pp.inserted_names,
                "source": "cache",
            }
        else:
            backends["ghidra"] = {
                "ok": False, "code": "", "lines": 0,
                "error": "Ghidra decompilation not cached for this function; "
                         "re-run analyze without --no-ghidra to populate.",
            }

    return {
        "project_id": project_id,
        "address": func.address,
        "name": func.name,
        "language": func.language,
        "source_backend": func.source_backend,
        "backends": backends,
    }


def _r2_decompile_sync(adapter, binary_path: str, address: str) -> dict:
    """Sync wrapper for the r2 adapter's decompile mode.

    Adapter.analyze is `async` but the body uses a blocking r2pipe. Calling
    it from `asyncio.to_thread` requires a sync entrypoint — this helper
    threads the call without spinning up a second loop.
    """
    import r2pipe
    r2 = r2pipe.open(binary_path, flags=["-2"])
    try:
        return adapter._decompile_one(r2, {"address": address})
    finally:
        r2.quit()
