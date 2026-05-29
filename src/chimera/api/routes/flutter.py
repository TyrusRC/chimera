"""B(l)utter Flutter/Dart extraction route.

POST /api/projects/{id}/flutter/extract
   Body: { "out_dir": "<absolute path>" }

Locates a libapp.so / App.framework binary inside the project's unpack
directory and runs B(l)utter against it. 503 when the `blutter` binary
isn't installed; 404 when the project hasn't been analyzed yet.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/projects/{project_id}/flutter", tags=["flutter"])
logger = logging.getLogger(__name__)


class ExtractRequest(BaseModel):
    out_dir: str
    libapp_override: str | None = None  # explicit binary path if auto-detect fails


@router.get("/status")
async def status(project_id: str) -> dict:
    from chimera.adapters.blutter_adapter import BlutterAdapter
    adapter = BlutterAdapter()
    return {
        "available": adapter.is_available(),
        "binary": adapter.binary_path() or "",
    }


@router.post("/extract")
async def extract(project_id: str, req: ExtractRequest) -> dict:
    from chimera.adapters.blutter_adapter import BlutterAdapter, detect_libapp
    from chimera.api.routes.projects import _store

    project = await _store.get(project_id)
    if not project or "model" not in project:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")

    adapter = BlutterAdapter()
    if not adapter.is_available():
        raise HTTPException(
            status_code=503,
            detail=("blutter binary not found. Install from "
                    "https://github.com/worawit/blutter and put it on "
                    "PATH or set CHIMERA_BLUTTER_BIN."),
        )

    libapp: Path | None
    if req.libapp_override:
        libapp = Path(req.libapp_override)
        if not libapp.exists():
            raise HTTPException(status_code=400,
                                detail=f"libapp_override not found: {req.libapp_override}")
    else:
        # Look in the project's unpack dir if recorded; fall back to the
        # binary's parent directory tree.
        unpack_root = project.get("unpack_dir") or project.get("path") or ""
        libapp = detect_libapp(Path(unpack_root).parent if Path(unpack_root).is_file()
                               else Path(unpack_root))
        if libapp is None:
            raise HTTPException(
                status_code=404,
                detail="No libapp.so or App.framework binary found in project tree. "
                       "Pass libapp_override.",
            )
    result = adapter.extract(libapp, req.out_dir)
    if not result.success:
        raise HTTPException(
            status_code=500,
            detail=f"blutter failed: {result.stderr[:500]}",
        )
    return {
        "libapp": str(libapp),
        "output_dir": str(result.output_dir),
        "classes_dumped": result.classes_dumped,
        "methods_dumped": result.methods_dumped,
        "stdout_tail": result.stdout[-500:] if result.stdout else "",
    }
