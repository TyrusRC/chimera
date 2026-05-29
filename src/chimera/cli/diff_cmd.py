"""chimera.cli — diff cmd commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.argument("a", type=str)
@click.argument("b", type=str)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--format", "fmt",
              type=click.Choice(["md", "json"]), default="md",
              help="Output format")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Write output to this file (default: stdout)")
def diff(a: str, b: str, cache_dir: str | None, fmt: str, out_path: str | None):
    """Diff two cached chimera projects.

    A and B can be sha256 hashes or unique sha256 prefixes (>= 8 chars).
    Both projects must already be cached — run `chimera analyze` first.
    """
    import json as _json
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.diff import (
        ProjectNotInCacheError, diff_projects, load_project,
        render_json, render_markdown,
    )

    config = ChimeraConfig(
        project_dir=Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    cache = AnalysisCache(config.cache_dir)

    try:
        snap_a = load_project(a, cache)
        snap_b = load_project(b, cache)
    except ProjectNotInCacheError as e:
        click.echo(f"project not in cache: {e}", err=True)
        raise SystemExit(2)
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(2)

    project_diff = diff_projects(snap_a, snap_b)

    if fmt == "json":
        text = _json.dumps(render_json(project_diff), indent=2)
    else:
        text = render_markdown(project_diff)

    if out_path:
        Path(out_path).write_text(text)
        click.echo(f"wrote {out_path}")
    else:
        click.echo(text)



# ----------------------------------------------------------------------
# diff-functions — BinDiff-style function similarity comparison
# ----------------------------------------------------------------------


@main.command("diff-functions")
@click.argument("a", type=click.Path(exists=True))
@click.argument("b", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--threshold", type=float, default=0.85,
              help="Minimum similarity to count as a match.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def diff_functions(a: str, b: str, project_dir: str | None,
                   cache_dir: str | None, threshold: float, fmt: str):
    """BinDiff-style function similarity between two binaries.

    Returns four sets: matched (high-similarity pairs), changed (low-
    similarity pairs by name), added (only in B), removed (only in A).
    """
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.diff.function_similarity import diff_models
    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    if cache_dir:
        kwargs["cache_dir"] = Path(cache_dir)
    cfg = ChimeraConfig(**kwargs)

    async def _run():
        engine = ChimeraEngine(cfg)
        return await engine.analyze(a), await engine.analyze(b)
    ma, mb = asyncio.run(_run())
    result = diff_models(ma, mb, threshold=threshold)
    if fmt == "json":
        click.echo(json.dumps(result, indent=2, sort_keys=True))
        return
    click.echo(f"[chimera] diff-functions {Path(a).name} → {Path(b).name}")
    click.echo(f"  matched:  {len(result['matched'])}")
    click.echo(f"  changed:  {len(result['changed'])}")
    click.echo(f"  added:    {len(result['added'])}")
    click.echo(f"  removed:  {len(result['removed'])}")
    for m in result["matched"][:20]:
        click.echo(f"    ~ {m['a_address']} → {m['b_address']}  "
                   f"{m['a_name']!r} → {m['b_name']!r}  sim={m['similarity']:.2f}")
    for m in result["changed"][:20]:
        click.echo(f"    ! {m['a_name']!r} drifted  "
                   f"a={m['a_address']} b={m['b_address']} sim={m['similarity']:.2f}")
