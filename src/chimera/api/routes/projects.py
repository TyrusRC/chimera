"""Project management routes — analyze binaries, list projects."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.api.path_guard import assert_analyzable_path
from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine

router = APIRouter(prefix="/api/projects", tags=["projects"])
logger = logging.getLogger(__name__)

# In-memory project store (bridge; a real DB-backed replacement is a follow-up
# sub-project). `_projects` is retained as the public alias used by other
# route modules (`functions.py`, `callgraph.py`, `strings.py`); `_store` is
# the lock-guarded wrapper used by writes.
_projects: dict[str, dict] = {}

_analysis_timeout: float = float(os.environ.get("CHIMERA_ANALYSIS_TIMEOUT_SEC", "1800"))


class _ProjectStore:
    """Lock-guarded wrapper around the shared `_projects` dict."""

    def __init__(self, data: dict[str, dict]) -> None:
        self._data = data
        self._lock = asyncio.Lock()
        self._tasks: dict[str, asyncio.Task] = {}

    async def get(self, pid: str) -> dict | None:
        async with self._lock:
            if pid in self._data:
                return dict(self._data[pid])
        # Miss: try the durable store (no-op unless CHIMERA_PERSIST + a DB).
        entry = await _rehydrate_from_db(pid)
        if entry is None:
            return None
        async with self._lock:
            self._data.setdefault(pid, entry)
            return dict(self._data[pid])

    async def set(self, pid: str, entry: dict) -> None:
        async with self._lock:
            self._evict_if_needed(pid)
            self._data[pid] = entry

    def _evict_if_needed(self, incoming_pid: str) -> None:
        """Bound the store so analyzed models (each large) can't grow the
        process without limit. NOTE: this is a RAM ceiling, not persistence —
        full Postgres-backed storage remains the durable follow-up (H2). Evicts
        the oldest non-in-flight project first. Cap via CHIMERA_MAX_PROJECTS.
        """
        try:
            cap = int(os.environ.get("CHIMERA_MAX_PROJECTS", "32"))
        except ValueError:
            cap = 32
        if cap <= 0 or incoming_pid in self._data or len(self._data) < cap:
            return
        for pid, entry in list(self._data.items()):
            if entry.get("status") != "analyzing":
                del self._data[pid]
                self._tasks.pop(pid, None)
                return
        # All in-flight (rare) — drop the oldest to honor the cap.
        oldest = next(iter(self._data))
        del self._data[oldest]
        self._tasks.pop(oldest, None)

    async def update(self, pid: str, **fields) -> None:
        async with self._lock:
            self._data.setdefault(pid, {}).update(fields)

    async def all_summaries(self) -> list[dict]:
        async with self._lock:
            return [dict(v, id=k) for k, v in self._data.items()]

    def register_task(self, pid: str, task: asyncio.Task) -> None:
        # Tasks are immutable references; no lock needed.
        self._tasks[pid] = task
        task.add_done_callback(lambda _t, pid=pid: self._tasks.pop(pid, None))

    def get_task(self, pid: str) -> asyncio.Task | None:
        return self._tasks.get(pid)


_store = _ProjectStore(_projects)


async def _rehydrate_from_db(pid: str) -> dict | None:
    """Best-effort rebuild of a project entry from durable storage on a store
    miss. Returns None (current behavior) unless persistence is enabled and the
    model is found — so restarts don't lose analyzed functions when a DB is
    configured."""
    from chimera.api.persistence import get_persistence
    model = await get_persistence().load_model(pid)
    if model is None:
        return None
    return {
        "name": Path(model.binary.path).name,
        "path": str(model.binary.path),
        "platform": model.binary.platform.value,
        "format": model.binary.format.value,
        "framework": model.binary.framework.value,
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "status": "complete",
        "model": model,
    }


_MANIFEST_FORMATS = {"apk", "aab", "xapk", "apkm"}
_MOBILE_FORMATS = _MANIFEST_FORMATS | {"ipa", "dex"}
_OBJC_FORMATS = {"ipa", "macho", "dylib", "fat"}


def _capabilities_for(fmt: str | None) -> dict[str, bool]:
    """Which analyst surfaces apply to this format.

    Used by the frontend to gate mobile-only panels (Frida, MASVS, manifest,
    network-security-config) for non-mobile binaries.
    """
    fmt = (fmt or "").lower()
    is_mobile = fmt in _MOBILE_FORMATS
    return {
        "frida": is_mobile,
        "masvs": is_mobile,
        "manifest": fmt in _MANIFEST_FORMATS,
        "network_security_config": fmt in _MANIFEST_FORMATS,
        "dotnet": fmt == "dotnet_pe",
        "objc": fmt in _OBJC_FORMATS,
    }


class AnalyzeRequest(BaseModel):
    path: str
    # NOTE: `ghidra_home` was intentionally removed. It previously flowed into
    # the executed `<ghidra_home>/support/analyzeHeadless` path, giving anyone
    # who could stage a directory (see the upload endpoint) code execution.
    # Ghidra location is now server-config/env only (GHIDRA_HOME).


class ProjectSummary(BaseModel):
    id: str
    name: str
    platform: str
    format: str
    framework: str
    function_count: int
    string_count: int
    status: str


@router.get("")
async def list_projects() -> list[dict]:
    return [
        {
            "id": entry["id"],
            "name": entry.get("name", "?"),
            "platform": entry.get("platform", "?"),
            "status": entry.get("status", "unknown"),
        }
        for entry in await _store.all_summaries()
    ]


@router.post("")
async def create_project(req: AnalyzeRequest) -> dict:
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {req.path}")
    assert_analyzable_path(path)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(path)
    project_id = binary.sha256[:16]

    await _store.set(project_id, {
        "name": path.name,
        "path": str(path),
        "platform": "detecting...",
        "status": "analyzing",
    })

    task = asyncio.create_task(_run_analysis(project_id, req))
    _store.register_task(project_id, task)
    return {"id": project_id, "status": "analyzing"}


@router.delete("/{project_id}")
async def cancel_project(project_id: str) -> dict:
    """Cancel the in-flight analysis task for a project, if any."""
    task = _store.get_task(project_id)
    if task is None or task.done():
        return {"ok": False, "reason": "no_active_task"}
    task.cancel()
    return {"ok": True}


async def _run_analysis(project_id: str, req: AnalyzeRequest) -> None:
    from chimera.api.websocket.analysis import update_progress

    config = ChimeraConfig()  # ghidra_home from server env (GHIDRA_HOME), not the request
    engine = ChimeraEngine(config)
    update_progress(project_id, "starting", "Initialising engine", 5)
    try:
        try:
            update_progress(project_id, "analyzing", "Running pipeline", 15)
            model = await asyncio.wait_for(
                engine.analyze(req.path), timeout=_analysis_timeout,
            )
            update_progress(project_id, "finalizing", "Storing results", 90)
            # Re-apply any persisted overlay (renames/types from prior runs)
            # so analyst work isn't lost across container restarts.
            try:
                from chimera.core.overlay import ProjectOverlay
                overlay = ProjectOverlay.load(config.project_dir, model.binary.sha256)
                touched = overlay.apply_to_model(model)
                if touched:
                    logger.info("overlay: re-applied %d annotations for %s",
                                touched, project_id)
            except Exception as exc:
                logger.warning("overlay re-apply failed for %s: %s", project_id, exc)
            await _store.update(
                project_id,
                platform=model.binary.platform.value,
                format=model.binary.format.value,
                framework=model.binary.framework.value,
                function_count=len(model.functions),
                string_count=len(model.get_strings()),
                status="complete",
                model=model,
            )
            # Write-through to durable storage (no-op unless CHIMERA_PERSIST +
            # a reachable DB) so analyzed functions survive a restart.
            try:
                from chimera.api.persistence import get_persistence
                if await get_persistence().save_model(model):
                    logger.info("persisted model for %s", project_id)
            except Exception as exc:  # noqa: BLE001 — never fail analysis on persistence
                logger.warning("persistence save error for %s: %s", project_id, exc)
            update_progress(project_id, "complete", "Analysis complete", 100)
            logger.info("Analysis complete for %s", project_id)
        except asyncio.TimeoutError:
            await _store.update(
                project_id, status=f"error: timeout after {_analysis_timeout}s",
            )
            update_progress(project_id, "error", f"Timeout after {_analysis_timeout}s", 100)
        except asyncio.CancelledError:
            await _store.update(project_id, status="cancelled")
            update_progress(project_id, "cancelled", "Cancelled by user", 100)
            raise
        except Exception as e:
            logger.error("Analysis failed for %s: %s", project_id, e)
            await _store.update(project_id, status=f"error: {e}")
            update_progress(project_id, "error", str(e), 100)
    finally:
        await engine.cleanup()


@router.get("/{project_id}")
async def get_project(project_id: str) -> dict:
    p = await _store.get(project_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Project not found")
    fmt = p.get("format")
    return {
        "id": project_id,
        "name": p.get("name"),
        "platform": p.get("platform"),
        "format": fmt or "?",
        "framework": p.get("framework", "?"),
        "function_count": p.get("function_count", 0),
        "string_count": p.get("string_count", 0),
        "finding_count": p.get("finding_count", 0),
        "status": p.get("status"),
        "capabilities": _capabilities_for(fmt),
    }
