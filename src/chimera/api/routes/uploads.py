"""File upload — POST /api/projects/upload stores the file and returns its path."""
from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _max_upload_bytes() -> int:
    try:
        mb = int(os.environ.get("CHIMERA_MAX_UPLOAD_MB", "4096"))
    except ValueError:
        mb = 4096
    return mb * 1024 * 1024


def _upload_ttl_seconds() -> int:
    try:
        return int(os.environ.get("CHIMERA_UPLOAD_TTL_SEC", str(24 * 3600)))
    except ValueError:
        return 24 * 3600


def _staging_dir() -> Path:
    """Where uploads land. Override via CHIMERA_UPLOAD_DIR for tests/deployments."""
    d = Path(os.environ.get("CHIMERA_UPLOAD_DIR", str(Path.home() / ".chimera" / "uploads")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _prune_stale(staging: Path) -> None:
    """Best-effort removal of uploads older than the TTL, so an unauthenticated
    upload endpoint can't slowly fill the disk."""
    ttl = _upload_ttl_seconds()
    if ttl <= 0:
        return
    cutoff = time.time() - ttl
    for child in staging.iterdir():
        try:
            if child.is_file() and child.stat().st_mtime < cutoff:
                child.unlink()
        except OSError:
            continue


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
    _prune_stale(staging)
    # Prepend a short uuid so concurrent uploads of same filename don't collide
    target = staging / f"{uuid.uuid4().hex[:8]}-{name}"
    # Stream to disk with a hard byte budget so an unauthenticated caller can't
    # exhaust the disk with one giant upload. Abort + clean up on overflow.
    limit = _max_upload_bytes()
    written = 0
    try:
        with target.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    fh.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"upload exceeds {limit // (1024 * 1024)} MB cap "
                               "(set CHIMERA_MAX_UPLOAD_MB to raise it)",
                    )
                fh.write(chunk)
    except HTTPException:
        raise
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"path": str(target), "filename": name, "size": written}
