"""chimera.cli — ioc cmd commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output file. Default: print summary to stdout.")
@click.option("--format", "fmt",
              type=click.Choice(["table", "json", "stix"]),
              default="table",
              help="Output format. 'stix' emits a STIX 2.1 JSON bundle.")
def ioc(path: str, project_dir: str | None, cache_dir: str | None,
        out_path: str | None, fmt: str):
    """Extract IoCs (URLs, IPs, domains, hashes, crypto addresses)."""
    asyncio.run(_ioc_cmd(path, project_dir, cache_dir, out_path, fmt))



async def _ioc_cmd(path, project_dir, cache_dir, out_path, fmt):
    import json as _json
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.ioc_scanner import scan_iocs, summarize
    from chimera.detection_engineering.stix_export import build_stix_bundle
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        matches = scan_iocs(model.get_strings())
        if fmt == "table":
            counts = summarize(matches)
            click.echo(f"IoC findings for {Path(path).name}:")
            click.echo()
            for cat in sorted(counts):
                click.echo(f"  {cat:14s} {counts[cat]:>4d}")
            click.echo()
            for cat in sorted({m.category for m in matches}):
                click.echo(f"[{cat}]")
                for m in [x for x in matches if x.category == cat][:25]:
                    addr = m.source_address or "—"
                    click.echo(f"  {m.confidence:>6}  {m.value}  ({addr})")
        elif fmt == "json":
            data = {
                "binary": {"sha256": model.binary.sha256, "path": str(model.binary.path)},
                "summary": summarize(matches),
                "matches": [m.to_dict() for m in matches],
            }
            text = _json.dumps(data, indent=2)
            if out_path:
                Path(out_path).write_text(text, encoding="utf-8")
                click.echo(f"Wrote {out_path}")
            else:
                click.echo(text)
        elif fmt == "stix":
            bundle = build_stix_bundle(model, matches)
            text = _json.dumps(bundle, indent=2)
            if out_path:
                Path(out_path).write_text(text, encoding="utf-8")
                click.echo(f"Wrote STIX bundle to {out_path}")
            else:
                click.echo(text)
    finally:
        await engine.cleanup()
