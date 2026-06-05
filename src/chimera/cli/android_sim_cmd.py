"""chimera.cli — android-similarity command (OAT-layer APK diffing).

Implements the Phrack 72:13 (Bleier & Lindorfer, Aug 2025) workflow
through chimera: APK -> dex2oat -> oatdump2binexport -> bindiff. The
heavy lifting lives in `chimera.pipelines.android_native_similarity`;
this module is just the Click entry point + human-readable rendering.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


@main.command("android-similarity")
@click.argument("apk_a", type=click.Path(exists=True, dir_okay=False))
@click.argument("apk_b", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", "out_dir", type=click.Path(), required=True,
              help="Output directory for OAT/BinExport/BinDiff artifacts.")
@click.option("--isa", type=str, default="arm64", show_default=True,
              help="dex2oat target instruction set (arm64, arm, x86_64, x86).")
def android_similarity(apk_a: str, apk_b: str, out_dir: str, isa: str):
    """Diff two Android APKs at the OAT (AOT-compiled) layer.

    Pipeline: APK -> classes.dex -> dex2oat -> oatdump2binexport ->
    bindiff. Catches similarities that survive DEX-level obfuscation
    (renaming, control-flow flattening at smali).

    Requires the following tools on PATH (or via env):
      * dex2oat              (Android AOSP host build-tools)
      * oatdump2binexport    (community; $CHIMERA_OATDUMP2BINEXPORT_BIN)
      * bindiff              (Google BinDiff v8+)

    Reference: Phrack 72:13 "Diffing Android Native Code via OAT" (2025).
    """
    from chimera.pipelines.android_native_similarity import diff_apks

    result = asyncio.run(diff_apks(
        Path(apk_a), Path(apk_b), out_dir=Path(out_dir), isa=isa,
    ))
    if not result.get("available", False):
        click.echo(f"[chimera] android-similarity unavailable: "
                   f"{result.get('error', 'unknown error')}", err=True)
        raise click.exceptions.Exit(2)
    if result.get("error"):
        click.echo(f"[chimera] android-similarity FAILED: {result['error']}",
                   err=True)
        raise click.exceptions.Exit(3)
    _render_summary(result)


def _render_summary(result: dict) -> None:
    """Print a compact human summary of the diff."""
    click.echo("=" * 60)
    click.echo("Android native similarity (OAT layer)")
    click.echo("=" * 60)
    click.echo(f"BinExport A:    {result.get('binexport_a')}")
    click.echo(f"BinExport B:    {result.get('binexport_b')}")
    click.echo(f"Functions A:    {result.get('functions_a', 0)}")
    click.echo(f"Functions B:    {result.get('functions_b', 0)}")
    click.echo(f"Matched fns:    {result.get('matched_functions', 0)}")
    mean = result.get("mean_similarity", 0.0)
    click.echo(f"Mean similarity:{mean:.3f}")
    click.echo(f"BinDiff db:     {result.get('bindiff_db')}")
    top = result.get("top_matches") or []
    if top:
        click.echo("")
        click.echo(f"Top {len(top)} matches by similarity:")
        click.echo(f"  {'sim':>6}  {'conf':>6}  A -> B")
        for m in top:
            sim = m.get("similarity", 0.0)
            conf = m.get("confidence", 0.0)
            name_a = (m.get("name_a") or "?")[:30]
            name_b = (m.get("name_b") or "?")[:30]
            click.echo(f"  {sim:>6.3f}  {conf:>6.3f}  {name_a} -> {name_b}")
    else:
        click.echo("(no per-function matches reported)")
