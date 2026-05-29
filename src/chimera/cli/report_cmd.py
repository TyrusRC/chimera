"""chimera.cli — report cmd commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output path. Defaults to <name>.report.{json,html}")
@click.option("--format", "fmt",
              type=click.Choice(["json", "html", "both", "masvs", "cvss", "sbom", "ir", "sarif"]),
              default="both",
              help="Output format(s). 'masvs' = MASVS coverage matrix; "
                   "'cvss' = CVSS finding draft (Markdown); "
                   "'sbom' = CycloneDX 1.6 SBOM (JSON); "
                   "'ir' = IR findings (Markdown, memory images only); "
                   "'sarif' = SARIF v2.1.0 findings (JSON).")
def report(path: str, project_dir: str | None, cache_dir: str | None,
           ghidra_home: str | None, out_path: str | None, fmt: str):
    """Run analysis and write a report for the analyst.

    Supported formats: JSON+HTML (default), MASVS coverage matrix,
    CVSS finding draft (Markdown), CycloneDX 1.6 SBOM, IR findings (Markdown).
    """
    asyncio.run(_report(path, project_dir, cache_dir, ghidra_home, out_path, fmt))



async def _report(path: str, project_dir: str | None, cache_dir: str | None,
                  ghidra_home: str | None, out_path: str | None, fmt: str):
    import json as _json
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.report import build_report, render_html

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        cache = AnalysisCache(config.cache_dir)

        base = Path(out_path) if out_path else Path.cwd() / f"{Path(path).stem}.report"
        wrote: list[str] = []

        if fmt in ("json", "both"):
            payload = build_report(model, cache)
            json_path = base.with_suffix(".json")
            json_path.write_text(_json.dumps(payload, indent=2))
            wrote.append(str(json_path))
        if fmt in ("html", "both"):
            payload = build_report(model, cache)
            html_path = base.with_suffix(".html")
            html_path.write_text(render_html(payload))
            wrote.append(str(html_path))
        if fmt == "masvs":
            from chimera.detection_engineering.masvs import build_masvs_matrix
            matrix = build_masvs_matrix(model, cache)
            masvs_path = base.with_suffix(".masvs.json")
            masvs_path.write_text(_json.dumps(matrix, indent=2))
            wrote.append(str(masvs_path))
        if fmt == "cvss":
            from chimera.detection_engineering.cvss_findings import (
                build_findings_from_chimera, render_findings_markdown,
            )
            findings = build_findings_from_chimera(model, cache)
            md_path = base.with_suffix(".cvss.md")
            md_path.write_text(render_findings_markdown(findings))
            wrote.append(str(md_path))
        if fmt == "sbom":
            from chimera.detection_engineering.cyclonedx_sbom import build_cyclonedx_sbom
            sbom = build_cyclonedx_sbom(model, cache)
            sbom_path = base.with_suffix(".sbom.json")
            sbom_path.write_text(_json.dumps(sbom, indent=2))
            wrote.append(str(sbom_path))
        if fmt == "ir":
            from chimera.detection_engineering.ir_findings import (
                build_ir_findings, render_ir_findings_markdown,
            )
            findings = build_ir_findings(model, cache)
            md_path = base.with_suffix(".ir.md")
            md_path.write_text(render_ir_findings_markdown(findings))
            wrote.append(str(md_path))
        if fmt == "sarif":
            from chimera.detection_engineering.cvss_findings import (
                build_findings_from_chimera,
            )
            from chimera.detection_engineering.sarif_export import findings_to_sarif
            findings = build_findings_from_chimera(model, cache)
            sarif_path = base.with_suffix(".sarif.json")
            sarif_path.write_text(_json.dumps(findings_to_sarif(findings), indent=2))
            wrote.append(str(sarif_path))

        click.echo(f"Report written for {Path(path).name}:")
        for p in wrote:
            click.echo(f"  {p}")
    finally:
        await engine.cleanup()
