"""chimera.cli — sdks cmd commands."""

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
@click.option("--ghidra-home", type=str, default=None)
def sdks(path: str, project_dir: str | None, cache_dir: str | None,
         ghidra_home: str | None):
    """Detect third-party SDKs in a mobile app."""
    asyncio.run(_sdks(path, project_dir, cache_dir, ghidra_home))



async def _sdks(path: str, project_dir: str | None, cache_dir: str | None,
                ghidra_home: str | None):
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.sdk.analyzer import SDKAnalyzer

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)

        # Prefer jadx-decompiled package list (already package-shaped) over
        # deriving from model.functions, which on Android often only holds
        # native funcs and won't surface JVM SDKs at all.
        packages: set[str] = set()
        cache = AnalysisCache(config.cache_dir)
        jadx_meta = cache.get_json(model.binary.sha256, "jadx") or {}
        for pkg in jadx_meta.get("packages", []) or []:
            if isinstance(pkg, str) and pkg:
                packages.add(pkg)
        # Fall back to model-derived packages for iOS / native-only inputs.
        for func in model.functions:
            if "." in func.name:
                packages.add(func.name.rsplit(".", 1)[0])

        analyzer = SDKAnalyzer()
        detected = analyzer.detect_from_packages(list(packages))
        summary = analyzer.summarize(detected)

        click.echo(f"SDKs detected in {Path(path).name}:")
        click.echo(f"  Total: {summary['total']}")
        for cat, names in summary["categories"].items():
            click.echo(f"  {cat}: {', '.join(names)}")
        if summary["suspicious"]:
            click.echo(f"\n  SUSPICIOUS: {', '.join(s['name'] for s in summary['suspicious'])}")
    finally:
        await engine.cleanup()
