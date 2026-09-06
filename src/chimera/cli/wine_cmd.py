"""chimera run-under-wine — run a Windows PE on Linux under Wine as a dynamic
oracle, isolated and observable (see the dynamic-analysis skill).

Runs in a throwaway WINEPREFIX with debug output silenced; console apps go
headless (stdout captured), GUI apps can use a virtual display (--xvfb), and a
--memory-scan needle is searched (ASCII + UTF-16LE) in the process memory for a
MessageBox/window answer. Executes an external binary — an explicit action.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("run-under-wine")
@click.argument("exe", type=click.Path(exists=True))
@click.argument("args", nargs=-1)
@click.option("--xvfb", is_flag=True, help="Run under a virtual display (GUI apps).")
@click.option("--timeout", type=float, default=30, help="Kill after N seconds.")
@click.option("--memory-scan", "memory_scan", default=None,
              help="Search process memory (ASCII+UTF-16LE) for this needle.")
@click.option("--prefix", default=None, help="Reuse an existing WINEPREFIX.")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def run_under_wine_cmd(exe, args, xvfb, timeout, memory_scan, prefix, as_json):
    """Run EXE (with ARGS) under Wine and report stdout/stderr + any memory hits."""
    from chimera.dynamic.wine import run_under_wine

    result = run_under_wine(
        exe, args, prefix=prefix, headless=not xvfb, xvfb=xvfb,
        timeout=timeout, memory_scan=memory_scan,
    )
    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return
    if not result.get("ran"):
        raise click.ClickException(result.get("error") or "wine run failed")
    click.echo(f"[chimera] wine exit={result['returncode']} "
               f"timed_out={result['timed_out']}  prefix={result['wineprefix']}")
    if result["stdout"]:
        click.echo("--- stdout ---")
        click.echo(result["stdout"])
    if result["stderr"].strip():
        click.echo("--- stderr ---")
        click.echo(result["stderr"])
    if result.get("memory_hits"):
        click.echo(f"--- memory hits: {result['memory_hits']}")
