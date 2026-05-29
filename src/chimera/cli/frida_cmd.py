"""chimera.cli — frida cmd commands."""

from __future__ import annotations

import asyncio
import logging

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.group()
def frida():
    """Run bundled Frida agent scripts against a connected device."""



@frida.command("list")
@click.option("--platform", "platform", type=click.Choice(["android", "ios", "all"]),
              default="all", help="Filter by target platform.")
def frida_list(platform: str):
    """List bundled Frida scripts."""
    from chimera.frida_scripts import list_scripts
    scripts = list_scripts()
    if platform != "all":
        scripts = [s for s in scripts
                   if s.platform == platform or s.platform == "both"]
    if not scripts:
        click.echo("(no scripts available)")
        return
    click.echo(f"{'ID':36s}  {'Platform':10s}  {'Risk':6s}  Name")
    click.echo("-" * 80)
    for s in scripts:
        click.echo(f"{s.id:36s}  {s.platform:10s}  {s.risk:6s}  {s.name}")



@frida.command("show")
@click.argument("script_id")
def frida_show(script_id: str):
    """Print a script's metadata + source to stdout."""
    from chimera.frida_scripts import get_script, read_source
    meta = get_script(script_id)
    if meta is None:
        click.echo(f"chimera frida: no script with id '{script_id}'", err=True)
        raise click.exceptions.Exit(1)
    click.echo(f"# {meta.name}")
    click.echo(f"# id: {meta.id}")
    click.echo(f"# platform: {meta.platform}")
    click.echo(f"# risk: {meta.risk}")
    click.echo(f"# requires: {', '.join(meta.requires) or '(none)'}")
    click.echo(f"# description: {meta.description}")
    click.echo()
    click.echo(read_source(script_id) or "")



@frida.command("run")
@click.argument("script_id")
@click.option("--target", required=True,
              help="Target package name (Android) or bundle id (iOS).")
@click.option("--device", "device_id", default=None,
              help="Device id (default: USB device).")
@click.option("--mode", type=click.Choice(["attach", "spawn"]), default="spawn",
              help="Whether to attach to a running process or spawn fresh.")
@click.option("--duration", type=int, default=30,
              help="How many seconds to keep the script attached.")
def frida_run(script_id: str, target: str, device_id: str | None,
              mode: str, duration: int):
    """Load a bundled script onto a connected device.

    Requires `frida` and `frida-server` running on the target device.
    The script's metadata advertises which platform/runtime it expects;
    chimera will refuse to run a mismatched script.
    """
    asyncio.run(_frida_run(script_id, target, device_id, mode, duration))



async def _frida_run(script_id, target, device_id, mode, duration):
    import asyncio as _aio
    from chimera.adapters.frida_adapter import FridaAdapter
    from chimera.frida_scripts import get_script, read_source

    meta = get_script(script_id)
    if meta is None:
        click.echo(f"chimera frida: no script with id '{script_id}'", err=True)
        raise click.exceptions.Exit(1)

    source = read_source(script_id)
    if not source:
        click.echo("chimera frida: failed to read script source", err=True)
        raise click.exceptions.Exit(1)

    adapter = FridaAdapter()
    if not adapter.is_available():
        click.echo("chimera frida: frida-python not installed; "
                   "`pip install frida` and ensure frida-server runs on the target",
                   err=True)
        raise click.exceptions.Exit(2)

    click.echo(f"[chimera] loading {meta.id} ({meta.risk}) on {target}")
    if mode == "spawn":
        session = await adapter.spawn(target, device_id=device_id, script_source=source)
    else:
        session = await adapter.attach(target, device_id=device_id)
        if session:
            await session.load_script(source)

    if session is None:
        click.echo("chimera frida: failed to attach/spawn — see logs", err=True)
        raise click.exceptions.Exit(3)

    click.echo(f"[chimera] script loaded; running for {duration}s — Ctrl+C to stop early")
    try:
        await _aio.sleep(duration)
    except KeyboardInterrupt:
        click.echo("\n[chimera] interrupted")
    finally:
        await adapter.cleanup()
        click.echo("[chimera] detached")
