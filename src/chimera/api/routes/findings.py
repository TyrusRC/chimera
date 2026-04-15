"""Findings query routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

router = APIRouter(prefix="/api/projects/{project_id}", tags=["findings"])


@router.get("/findings")
async def list_findings(
    project_id: str,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    from chimera.api.routes.projects import _projects
    p = _projects.get(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = p.get("findings", [])

    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    if rule_id:
        findings = [f for f in findings if f.rule_id == rule_id]

    total = len(findings)
    findings = findings[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/findings/{finding_index}")
async def get_finding(project_id: str, finding_index: int) -> dict:
    from chimera.api.routes.projects import _projects
    p = _projects.get(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = p.get("findings", [])
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")

    return findings[finding_index].to_dict()
