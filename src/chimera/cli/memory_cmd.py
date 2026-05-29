"""chimera.cli — memory cmd commands."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.group(invoke_without_command=True)
@click.argument("path", type=click.Path(), required=False)
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.pass_context
def memory(ctx, path: str | None,
           project_dir: str | None, cache_dir: str | None):
    """Triage a Linux memory image via Volatility 3.

    Run with no subcommand for the full pipeline; use `pslist`, `netstat`,
    `malfind`, or `findings` to print one section at a time from cache.
    """
    ctx.ensure_object(dict)
    ctx.obj["project_dir"] = project_dir
    ctx.obj["cache_dir"] = cache_dir
    if ctx.invoked_subcommand is None:
        if not path:
            click.echo("chimera memory: PATH is required when no subcommand is given.",
                       err=True)
            raise click.exceptions.Exit(1)
        if not Path(path).exists():
            click.echo(f"chimera memory: path does not exist: {path}", err=True)
            raise click.exceptions.Exit(1)
        ctx.obj["path"] = path
        asyncio.run(_memory_full(path, project_dir, cache_dir))
        return
    ctx.obj["path"] = path  # may be None; subcommands enforce as needed



async def _memory_full(path, project_dir, cache_dir):
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
        summary = cache.get_json(model.binary.sha256, "memory_protection") or {}
        click.echo(f"Memory triage for {Path(path).name}:")
        click.echo()
        for key, label in [
            ("process_count", "Processes"),
            ("kernel_thread_count", "  Kernel threads"),
            ("bash_command_count", "Bash commands recovered"),
            ("network_connection_count", "Network connections"),
            ("malfind_hit_count", "Malfind RWX hits"),
            ("kernel_module_count", "Kernel modules"),
            ("hidden_module_count", "  Hidden modules"),
            ("hooked_syscall_count", "  Hooked syscalls"),
            ("persistence_finding_count", "Persistence findings"),
        ]:
            click.echo(f"  {label:32s} {summary.get(key, 0)}")
    finally:
        await engine.cleanup()



def _ensure_path(ctx) -> str:
    path = ctx.obj.get("path")
    if not path:
        click.echo("chimera memory <subcommand>: PATH argument is required",
                   err=True)
        raise click.exceptions.Exit(1)
    return path



@memory.command("pslist")
@click.pass_context
def memory_pslist(ctx):
    """Print the process list from cached memory analysis."""
    asyncio.run(_memory_section(ctx, "vol_pslist", _print_pslist))



@memory.command("netstat")
@click.pass_context
def memory_netstat(ctx):
    """Print recovered network connections."""
    asyncio.run(_memory_section(ctx, "vol_netstat", _print_netstat))



@memory.command("malfind")
@click.pass_context
def memory_malfind(ctx):
    """Print malfind hits (RWX VMA regions)."""
    asyncio.run(_memory_section(ctx, "vol_malfind", _print_malfind))



@memory.command("findings")
@click.pass_context
def memory_findings(ctx):
    """Print auto-stub IR findings."""
    asyncio.run(_memory_findings(ctx))



async def _memory_section(ctx, cache_key, printer):
    path = _ensure_path(ctx)
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(ctx.obj.get("project_dir")) if ctx.obj.get("project_dir")
                    else Path.cwd() / "chimera_project",
        cache_dir=Path(ctx.obj.get("cache_dir")) if ctx.obj.get("cache_dir")
                  else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        blob = cache.get_json(model.binary.sha256, cache_key) or {}
        printer(blob)
    finally:
        await engine.cleanup()



async def _memory_findings(ctx):
    path = _ensure_path(ctx)
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.ir_findings import (
        build_ir_findings, render_ir_findings_markdown,
    )
    config = ChimeraConfig(
        project_dir=Path(ctx.obj.get("project_dir")) if ctx.obj.get("project_dir")
                    else Path.cwd() / "chimera_project",
        cache_dir=Path(ctx.obj.get("cache_dir")) if ctx.obj.get("cache_dir")
                  else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        findings = build_ir_findings(model, cache)
        click.echo(render_ir_findings_markdown(findings))
    finally:
        await engine.cleanup()



def _print_pslist(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no processes recorded — pipeline may not have run)")
        return
    click.echo(f"{'PID':>6}  {'PPID':>6}  {'KTHR':>4}  NAME")
    for r in rows[:200]:
        kthr = "y" if r.get("is_kernel_thread") else " "
        click.echo(f"{r.get('pid', '?'):>6}  {r.get('ppid', '?'):>6}  {kthr:>4}  {r.get('name', '?')}")
    if len(rows) > 200:
        click.echo(f"... +{len(rows) - 200} more")



def _print_netstat(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no connections recorded)")
        return
    click.echo(f"{'PROTO':<8}  {'STATE':<14}  {'LOCAL':<24}  {'REMOTE':<24}  PID")
    for r in rows[:200]:
        click.echo(f"{r.get('protocol', '?'):<8}  {r.get('state', '?'):<14}  "
                   f"{r.get('local', '?'):<24}  {r.get('remote', '?'):<24}  {r.get('pid', '?')}")



def _print_malfind(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no malfind hits)")
        return
    click.echo(f"{'PID':>6}  {'PROCESS':<16}  {'PROT':<6}  {'START':<16}  END")
    for r in rows[:100]:
        click.echo(f"{r.get('pid', '?'):>6}  {r.get('process', '?'):<16}  "
                   f"{r.get('protection', '?'):<6}  {r.get('start_addr', '?'):<16}  "
                   f"{r.get('end_addr', '?')}")
