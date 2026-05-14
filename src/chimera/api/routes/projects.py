"""Project management routes — analyze binaries, list projects."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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
            return dict(self._data[pid]) if pid in self._data else None

    async def set(self, pid: str, entry: dict) -> None:
        async with self._lock:
            self._data[pid] = entry

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
    ghidra_home: Optional[str] = None


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
    config = ChimeraConfig(ghidra_home=req.ghidra_home)
    engine = ChimeraEngine(config)
    try:
        try:
            model = await asyncio.wait_for(
                engine.analyze(req.path), timeout=_analysis_timeout,
            )
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
            logger.info("Analysis complete for %s", project_id)
        except asyncio.TimeoutError:
            await _store.update(
                project_id, status=f"error: timeout after {_analysis_timeout}s",
            )
        except asyncio.CancelledError:
            await _store.update(project_id, status="cancelled")
            raise
        except Exception as e:
            logger.error("Analysis failed for %s: %s", project_id, e)
            await _store.update(project_id, status=f"error: {e}")
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
