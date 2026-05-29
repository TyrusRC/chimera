"""chimera.cli — imports cmd commands."""

from __future__ import annotations

import asyncio
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
@click.option("--bucket", type=str, default=None,
              help="Filter to a single bucket (process_injection, anti_debug, ...)")
@click.option("--min-score", type=int, default=0,
              help="Hide buckets with score below this threshold")
def imports(path: str, project_dir: str | None, cache_dir: str | None,
            bucket: str | None, min_score: int):
    """List suspicious PE imports with bucket scoring."""
    asyncio.run(_imports_cmd(path, project_dir, cache_dir, bucket, min_score))



async def _imports_cmd(path, project_dir, cache_dir, bucket_filter, min_score):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        # pe_imports cache wraps the bucket dict under "bucket_summary" alongside
        # a "scored_count" total; iterate the nested map, not the wrapper.
        raw = cache.get_json(model.binary.sha256, "pe_imports") or {}
        scored = raw.get("bucket_summary") or {}
        if not scored:
            click.echo("No PE import scoring available (input may not be a PE).")
            return
        # Sort buckets by weight*score descending
        rows = []
        for b, info in scored.items():
            score = info.get("score", 0)
            weight = info.get("weight", 1.0)
            if score < min_score:
                continue
            if bucket_filter and b != bucket_filter:
                continue
            rows.append((b, score, weight, info.get("imports", [])))
        rows.sort(key=lambda r: -(r[1] * r[2]))
        click.echo(f"PE import scoring for {Path(path).name}:")
        click.echo()
        for b, score, weight, imports_list in rows:
            click.echo(f"  {b:20s} score={score:3d}  weight={weight:>4.1f}")
            preview = ", ".join(imports_list[:6])
            if len(imports_list) > 6:
                preview += f", ... +{len(imports_list) - 6} more"
            click.echo(f"    {preview}")
    finally:
        await engine.cleanup()
