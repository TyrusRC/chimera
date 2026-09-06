"""chimera.cli — varbert cmd commands."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera.cli._root import main
from chimera.cli.ai_cmd import _ai_decompile

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# varbert — S&P 2024 variable-name recovery (optional [varbert] extra)
# ----------------------------------------------------------------------


@main.group()
def varbert():
    """Pal et al. 2024 — recover variable names from decompiled output.

    Requires the optional `varbert-api` package (not on PyPI). Install
    from source: pip install "git+https://github.com/binsync/varbert_api".
    """



@varbert.command("rename")
@click.argument("path", type=click.Path(exists=True))
@click.argument("address", type=str)
@click.option("--variant", type=str, default="ghidra-O2",
              help="Pretrained model variant (e.g. ghidra-O0, ida-O2).")
@click.option("--apply/--preview", default=False,
              help="Write recovered names to overlay (default: preview).")
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="ghidra")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def varbert_rename(path: str, address: str, variant: str, apply: bool,
                   backend: str, project_dir: str | None, cache_dir: str | None):
    """Recover variable names for the function at ADDRESS."""
    from chimera.adapters.varbert_adapter import VarBertAdapter
    from chimera.core.overlay import ProjectOverlay

    adapter = VarBertAdapter(model_variant=variant)
    if not adapter.is_available():
        raise click.ClickException(
            "VarBERT not installed (varbert-api is not on PyPI). Install from "
            "source: pip install \"git+https://github.com/binsync/varbert_api\"."
        )

    code, _name = _ai_decompile(path, address, project_dir, cache_dir, backend)
    renames = adapter.rename_function(code, function_address=address)
    if not renames:
        click.echo("[chimera] varbert: no renames suggested")
        return

    click.echo(f"[chimera] varbert: {len(renames)} suggestions for {address}")
    for r in renames:
        marker = "✓" if apply else " "
        click.echo(f"  {marker} {r.original!r} → {r.recovered!r}  "
                   f"conf={r.confidence:.2f}")

    if apply:
        from chimera.core.config import ChimeraConfig
        from chimera.core.engine import ChimeraEngine
        kwargs: dict = {}
        if project_dir:
            kwargs["project_dir"] = Path(project_dir)
        if cache_dir:
            kwargs["cache_dir"] = Path(cache_dir)
        cfg = ChimeraConfig(**kwargs)
        engine = ChimeraEngine(cfg)
        model = asyncio.run(engine.analyze(path))
        overlay = ProjectOverlay.load(cfg.project_dir, model.binary.sha256)
        for r in renames:
            overlay.rename_variable(address, r.original, r.recovered)
        overlay.save()
        click.echo(f"[chimera] varbert: {len(renames)} renames written to overlay")
