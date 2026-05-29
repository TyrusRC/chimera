"""chimera.cli — persistence cmd commands."""

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
def persistence(path: str, project_dir: str | None, cache_dir: str | None):
    """List persistence-relevant strings recovered from a Linux ELF binary."""
    asyncio.run(_persistence_cmd(path, project_dir, cache_dir))



async def _persistence_cmd(path, project_dir, cache_dir):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.pipelines.common import detect_platform
    plat = detect_platform(Path(path))
    if plat != "linux_native":
        click.echo(f"chimera persistence: input is not a standalone Linux ELF (detected: {plat})", err=True)
        raise click.exceptions.Exit(1)

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        raw = cache.get_json(model.binary.sha256, "elf_persistence") or []
        rows = raw.get("hits") if isinstance(raw, dict) else raw
        if not rows:
            click.echo("No persistence-relevant strings detected.")
            return
        # Group by category
        by_cat: dict[str, list] = {}
        for r in rows:
            by_cat.setdefault(r.get("category", "?"), []).append(r)
        click.echo(f"ELF persistence findings for {Path(path).name}:")
        click.echo()
        for cat in sorted(by_cat):
            entries = by_cat[cat]
            click.echo(f"  [{cat}] {len(entries)} match(es)")
            for e in entries[:6]:
                addr = e.get("string_address") or "—"
                click.echo(f"    {addr:>12}  {e.get('path', '')}")
            if len(entries) > 6:
                click.echo(f"    ... +{len(entries) - 6} more")
    finally:
        await engine.cleanup()
