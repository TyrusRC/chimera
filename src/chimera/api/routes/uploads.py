"""File upload — POST /api/projects/upload stores the file and returns its path."""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _staging_dir() -> Path:
    """Where uploads land. Override via CHIMERA_UPLOAD_DIR for tests/deployments."""
    d = Path(os.environ.get("CHIMERA_UPLOAD_DIR", str(Path.home() / ".chimera" / "uploads")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_filename(name: str) -> str:
    """Strip directory components from a client-supplied filename."""
    # Reject anything with path separators after Path() normalization
    candidate = Path(name).name
    if not candidate or candidate in (".", ".."):
        raise HTTPException(status_code=400, detail="invalid filename")
    return candidate


@router.post("/upload")
async def upload_project(file: UploadFile) -> dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="missing filename")
    name = _safe_filename(file.filename)
    staging = _staging_dir()
    # Prepend a short uuid so concurrent uploads of same filename don't collide
    target = staging / f"{uuid.uuid4().hex[:8]}-{name}"
    with target.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)
    return {"path": str(target), "filename": name, "size": target.stat().st_size}
