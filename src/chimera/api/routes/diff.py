"""POST /api/diff — diff two cached projects' findings + manifest deltas."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chimera.api.routes.projects import _store
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.diff.engine import diff_projects as _diff
from chimera.diff.loader import ProjectNotInCacheError, load_project


def _cache_dir() -> Path:
    """Pick the cache dir to query. Honors CHIMERA_CACHE_DIR for test override."""
    override = os.environ.get("CHIMERA_CACHE_DIR")
    return Path(override) if override else ChimeraConfig().cache_dir

router = APIRouter(prefix="/api", tags=["diff"])
logger = logging.getLogger(__name__)


class DiffRequest(BaseModel):
    a: str
    b: str


class FunctionDiffRequest(BaseModel):
    a: str
    b: str
    threshold: float = 0.85


def _finding_to_dict(f) -> dict:
    return {
        "finding_id": getattr(f, "finding_id", None),
        "title": getattr(f, "title", None),
        "severity": getattr(f, "severity", None),
        "cvss_vector": getattr(f, "cvss_vector", None),
        "cvss_base_score": getattr(f, "cvss_base_score", None),
        "evidence": list(getattr(f, "evidence", []) or []),
    }


def _component_to_dict(c) -> dict:
    return {
        "kind": getattr(c, "kind", None),
        "name": getattr(c, "name", None),
        "exported": getattr(c, "exported", None),
        "has_intent_filter": getattr(c, "has_intent_filter", None),
    }


def _native_lib_to_dict(nl) -> dict:
    return {
        "lib": getattr(nl, "lib", None),
        "kind": getattr(nl, "kind", None),
        "detail": getattr(nl, "detail", None),
    }


@router.post("/diff")
async def diff(req: DiffRequest) -> dict:
    """Compare two projects (identified by their 16-char ids or full sha256)
    and return added/resolved findings plus manifest/SDK/native-lib deltas.

    A project is "knowable" if it has cache state (the source of truth for diff).
    The in-memory project store is consulted only to surface a clearer 404 when
    neither store nor cache knows the id.
    """
    cache = AnalysisCache(_cache_dir())
    try:
        snap_a = load_project(req.a, cache)
        snap_b = load_project(req.b, cache)
    except ProjectNotInCacheError as e:
        # Fall back to the in-memory store for a friendlier error.
        missing = []
        for name, spec in (("a", req.a), ("b", req.b)):
            try:
                load_project(spec, cache)
            except ProjectNotInCacheError:
                if await _store.get(spec) is None:
                    missing.append(name)
        detail = f"Project not in cache: {e}"
        if missing:
            detail = f"Project(s) not found: {','.join(missing)}"
        raise HTTPException(status_code=404, detail=detail)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = _diff(snap_a, snap_b)
    return {
        "a_sha256": result.a_sha256,
        "b_sha256": result.b_sha256,
        "permissions_added": list(result.permissions_added),
        "permissions_removed": list(result.permissions_removed),
        "exported_added": [_component_to_dict(c) for c in result.exported_added],
        "exported_removed": [_component_to_dict(c) for c in result.exported_removed],
        "sdks_added": list(result.sdks_added),
        "sdks_removed": list(result.sdks_removed),
        "native_libs_added": [_native_lib_to_dict(n) for n in result.native_libs_added],
        "native_libs_removed": [_native_lib_to_dict(n) for n in result.native_libs_removed],
        "native_libs_changed": [_native_lib_to_dict(n) for n in result.native_libs_changed],
        "findings_added": [_finding_to_dict(f) for f in result.findings_added],
        "findings_resolved": [_finding_to_dict(f) for f in result.findings_resolved],
    }


@router.post("/diff/functions")
async def diff_functions(req: FunctionDiffRequest) -> dict:
    """BinDiff-style per-function similarity comparison.

    Both `a` and `b` must be project IDs currently in the in-memory store
    (i.e. analyzed in this server's lifetime). We use the live models —
    not the cached snapshot — so analyst renames in the overlay are
    reflected in the matching.
    """
    from chimera.diff.function_similarity import diff_models

    proj_a = await _store.get(req.a)
    proj_b = await _store.get(req.b)
    if not proj_a or "model" not in proj_a:
        raise HTTPException(status_code=404, detail=f"Project {req.a!r} not analyzed yet")
    if not proj_b or "model" not in proj_b:
        raise HTTPException(status_code=404, detail=f"Project {req.b!r} not analyzed yet")
    return diff_models(proj_a["model"], proj_b["model"], threshold=req.threshold)
