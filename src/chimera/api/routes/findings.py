"""Findings + report export routes.

GET /api/projects/{id}/findings        — analyst-facing findings list.
GET /api/projects/{id}/export/{format} — full report in json/markdown/sarif/html.

Findings are derived from the same `cvss_findings.build_findings_from_chimera`
pipeline the CLI report uses, so the web UI sees the same data as `chimera report
--format cvss`.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Response

router = APIRouter(prefix="/api/projects/{project_id}", tags=["findings"])
logger = logging.getLogger(__name__)


async def _get_project(project_id: str) -> dict:
    from chimera.api.routes.projects import _store
    p = await _store.get(project_id)
    if not p or "model" not in p:
        raise HTTPException(status_code=404, detail="Project not analyzed yet")
    return p


@router.get("/findings")
async def list_findings(project_id: str) -> dict:
    """Return the list of CVSS findings derived from the analyzed model."""
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.detection_engineering.cvss_findings import build_findings_from_chimera

    project = await _get_project(project_id)
    model = project["model"]
    cache = AnalysisCache(ChimeraConfig().cache_dir)
    findings = build_findings_from_chimera(model, cache)
    return {
        "project_id": project_id,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/export/{fmt}")
async def export_report(project_id: str, fmt: str) -> Response:
    """Render the report in the requested format.

    Supported: json, html, markdown, sarif. The web UI's Export button posts
    `markdown` or `sarif` — both are produced from the same finding set so
    they stay in sync.
    """
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.detection_engineering.cvss_findings import (
        build_findings_from_chimera,
        render_findings_markdown,
    )
    from chimera.detection_engineering.sarif_export import findings_to_sarif
    from chimera.report import build_report, render_html

    project = await _get_project(project_id)
    model = project["model"]
    cache = AnalysisCache(ChimeraConfig().cache_dir)

    fmt = fmt.lower()
    if fmt == "json":
        payload = build_report(model, cache)
        return Response(json.dumps(payload, indent=2), media_type="application/json")
    if fmt == "html":
        payload = build_report(model, cache)
        return Response(render_html(payload), media_type="text/html")
    if fmt == "markdown":
        findings = build_findings_from_chimera(model, cache)
        # Always emit a binary-metadata header so a "no findings" run still
        # produces a useful artefact analysts can paste into their report.
        b = model.binary
        name = b.path.name if hasattr(b.path, "name") else (str(b.path).rsplit("/", 1)[-1] or b.sha256[:12])
        header = (
            f"# Chimera report — {name}\n\n"
            f"- **SHA-256:** `{b.sha256}`\n"
            f"- **Format:** {getattr(b.format, 'value', b.format)}\n"
            f"- **Platform:** {getattr(b.platform, 'value', b.platform)}\n"
            f"- **Arch:** {getattr(b.arch, 'value', b.arch)}\n"
            f"- **Size:** {b.size_bytes:,} bytes\n"
            f"- **Functions:** {len(model.functions)}\n"
            f"- **Strings:** {len(list(model.get_strings()))}\n\n"
            "## Findings\n\n"
        )
        return Response(header + render_findings_markdown(findings), media_type="text/markdown")
    if fmt == "sarif":
        findings = build_findings_from_chimera(model, cache)
        return Response(
            json.dumps(findings_to_sarif(findings), indent=2),
            media_type="application/sarif+json",
        )
    raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")
