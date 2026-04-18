"""Project management routes — analyze binaries, list projects."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine

router = APIRouter(prefix="/api/projects", tags=["projects"])
logger = logging.getLogger(__name__)

# In-memory project store (replaced by DB in production)
_projects: dict[str, dict] = {}


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
            "id": pid,
            "name": p.get("name", "?"),
            "platform": p.get("platform", "?"),
            "status": p.get("status", "unknown"),
        }
        for pid, p in _projects.items()
    ]


@router.post("")
async def create_project(req: AnalyzeRequest, background_tasks: BackgroundTasks) -> dict:
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {req.path}")

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(path)
    project_id = binary.sha256[:16]

    _projects[project_id] = {
        "name": path.name,
        "path": str(path),
        "platform": "detecting...",
        "status": "analyzing",
    }

    background_tasks.add_task(_run_analysis, project_id, req)
    return {"id": project_id, "status": "analyzing"}


async def _run_analysis(project_id: str, req: AnalyzeRequest):
    try:
        config = ChimeraConfig(ghidra_home=req.ghidra_home)
        engine = ChimeraEngine(config)
        model = await engine.analyze(req.path)

        _projects[project_id].update({
            "platform": model.binary.platform.value,
            "format": model.binary.format.value,
            "framework": model.binary.framework.value,
            "function_count": len(model.functions),
            "string_count": len(model.get_strings()),
            "status": "complete",
            "model": model,
        })
        logger.info("Analysis complete for %s", project_id)
    except Exception as e:
        logger.error("Analysis failed for %s: %s", project_id, e)
        _projects[project_id]["status"] = f"error: {e}"


@router.get("/{project_id}")
async def get_project(project_id: str) -> dict:
    if project_id not in _projects:
        raise HTTPException(status_code=404, detail="Project not found")
    p = _projects[project_id]
    return {
        "id": project_id,
        "name": p.get("name"),
        "platform": p.get("platform"),
        "format": p.get("format", "?"),
        "framework": p.get("framework", "?"),
        "function_count": p.get("function_count", 0),
        "string_count": p.get("string_count", 0),
        "finding_count": p.get("finding_count", 0),
        "status": p.get("status"),
    }
