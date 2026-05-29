"""chimera.cli — manifest cmd commands."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from chimera.cli._common import _load_cache_and_sha
from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--format", "fmt",
              type=click.Choice(["text", "json"]),
              default="text",
              help="Output format")
def manifest(path: str, project_dir: str | None, cache_dir: str | None, fmt: str):
    """Print AndroidManifest + network_security_config findings.

    Requires the project to have been analyzed (chimera analyze <path>) so
    the manifest XML is in cache.
    """
    import json as _json
    import tempfile
    from chimera.parsers.android_manifest import parse_manifest as _pm
    from chimera.parsers.network_security_config import parse_nsc as _pn
    from chimera.detection_engineering.manifest_findings import build_findings_from_models

    cache, sha = _load_cache_and_sha(path, project_dir, cache_dir)
    manifest_bytes = cache.get(sha, "manifest_xml")
    if manifest_bytes is None:
        click.echo("No manifest_xml in cache. Run `chimera analyze` first.", err=True)
        raise SystemExit(2)

    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "AndroidManifest.xml"
        mp.write_bytes(manifest_bytes)
        manifest_model = _pm(mp)
        nsc_bytes = cache.get(sha, "nsc_xml")
        nsc_model = None
        if nsc_bytes:
            np = Path(td) / "network_security_config.xml"
            np.write_bytes(nsc_bytes)
            nsc_model = _pn(np)

        findings = build_findings_from_models(manifest_model, nsc=nsc_model)

    if fmt == "json":
        click.echo(_json.dumps([f.to_dict() for f in findings], indent=2))
        return

    if not findings:
        click.echo("No manifest/NSC findings.")
        return
    click.echo(f"{len(findings)} finding(s):")
    for f in findings:
        click.echo(f"  [{f.severity}] {f.finding_id}: {f.title}")
        for ev in f.evidence:
            click.echo(f"    - {ev}")
        if f.recommendation:
            click.echo(f"    fix: {f.recommendation}")
