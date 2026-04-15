"""Report export route."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/api/projects/{project_id}", tags=["export"])

_SUPPORTED_FORMATS = {"sarif", "json", "markdown"}


@router.get("/export/{format}")
async def export_report(project_id: str, format: str) -> PlainTextResponse:
    if format not in _SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format!r}. Supported: {sorted(_SUPPORTED_FORMATS)}")

    from chimera.api.routes.projects import _projects

    p = _projects.get(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = p.get("findings", [])
    binary_info = {
        "name": p.get("name"),
        "sha256": project_id,
        "platform": p.get("platform", "?"),
        "format": p.get("format", "?"),
    }

    if format == "sarif":
        from chimera.report.sarif import generate_sarif

        return PlainTextResponse(generate_sarif(findings), media_type="application/json")
    elif format == "json":
        from chimera.report.json_report import generate_json

        return PlainTextResponse(generate_json(findings, binary_info), media_type="application/json")
    elif format == "markdown":
        from chimera.report.markdown import generate_markdown

        return PlainTextResponse(generate_markdown(findings, binary_info), media_type="text/markdown")

    # Should be unreachable after the guard above
    raise HTTPException(status_code=400, detail=f"Unknown format: {format}")
