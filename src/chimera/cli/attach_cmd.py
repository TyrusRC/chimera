"""chimera.cli — attach cmd commands."""

from __future__ import annotations

import asyncio
import logging

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# attach — Frida-driven runtime hook session with bundled bypasses
# ----------------------------------------------------------------------


@main.command("attach")
@click.option("--pid", type=int, default=None,
              help="Attach to a local host process by PID.")
@click.option("--target", "target", type=str, default=None,
              help="Target package/bundle id (mobile) or process name.")
@click.option("--device", "device_id", default=None,
              help="Frida device id. Use 'local' for the host machine "
                   "(default: USB-attached mobile device).")
@click.option("--bypass", "bypasses", multiple=True,
              help="Bundled script id to preload (repeatable). "
                   "See `chimera frida list` for available ids.")
@click.option("--mode", type=click.Choice(["attach", "spawn"]), default="attach",
              help="Whether to attach to a running process or spawn fresh "
                   "(spawn requires --target).")
@click.option("--duration", type=int, default=30,
              help="Seconds to keep the session alive. Pair with --interactive "
                   "to read commands from stdin instead of sleeping.")
@click.option("--interactive", is_flag=True,
              help="Drop into a tiny REPL after preloading bypasses: each "
                   "line of stdin is evaluated against the attached session.")
@click.option("--print-messages/--no-print-messages", default=True,
              help="Stream the script's send()/console.log() messages to stdout.")
def attach(pid: int | None, target: str | None, device_id: str | None,
           bypasses: tuple[str, ...], mode: str, duration: int,
           interactive: bool, print_messages: bool):
    """Attach Frida to a target and preload bundled bypass scripts.

    \b
    Examples:
      # Hook a running mobile app and silence root + SSL pinning checks.
      chimera attach --target com.example.app --bypass root_bypass --bypass ssl_pinning

      # Spawn fresh so the bypasses run before the first anti-debug check.
      chimera attach --target com.example.app --mode spawn --bypass anti_debug

      # Attach to a local host process by PID.
      chimera attach --pid 1234 --device local --bypass ssl_pinning

      # Drop into a console — each stdin line is evaluated in the agent.
      chimera attach --target com.example.app --interactive
    """
    if pid is None and not target:
        raise click.UsageError("provide --pid or --target")
    if mode == "spawn" and not target:
        raise click.UsageError("--mode spawn requires --target (package/bundle id)")
    asyncio.run(_attach_cmd(
        pid=pid, target=target, device_id=device_id,
        bypasses=bypasses, mode=mode, duration=duration,
        interactive=interactive, print_messages=print_messages,
    ))



async def _attach_cmd(*, pid, target, device_id, bypasses, mode, duration,
                      interactive, print_messages):
    import asyncio as _aio
    from chimera.adapters.frida_adapter import FridaAdapter
    from chimera.frida_scripts import get_script, read_source

    # Resolve & validate every bypass up-front so we don't half-load a
    # session before discovering one was misspelled.
    resolved: list[tuple[str, str]] = []  # [(script_id, source), ...]
    for script_id in bypasses:
        meta = get_script(script_id)
        if meta is None:
            click.echo(f"chimera attach: unknown script id {script_id!r}", err=True)
            raise click.exceptions.Exit(1)
        source = read_source(script_id)
        if not source:
            click.echo(f"chimera attach: empty script source for {script_id!r}", err=True)
            raise click.exceptions.Exit(1)
        resolved.append((script_id, source))

    adapter = FridaAdapter()
    if not adapter.is_available():
        click.echo(
            "chimera attach: frida-python not installed. "
            "Install with `pip install frida` and ensure frida-server is "
            "reachable on the target.", err=True,
        )
        raise click.exceptions.Exit(2)

    target_repr = f"pid={pid}" if pid is not None else target
    click.echo(f"[chimera] {mode} -> {target_repr} ({device_id or 'usb'})")

    if mode == "spawn":
        # We don't preload via spawn() because we want multi-script support.
        # Spawn-with-suspend gives us a window to load every bypass *before*
        # the app code runs — load_script + later device.resume().
        session = await adapter.spawn(target, device_id=device_id)
    else:
        attach_target = pid if pid is not None else target
        session = await adapter.attach(attach_target, device_id=device_id)

    if session is None:
        click.echo("chimera attach: failed to attach (see logs)", err=True)
        raise click.exceptions.Exit(3)

    # Preload bypasses sequentially. Each load_script registers its own
    # on_message handler; FridaSession aggregates them into .messages.
    for script_id, source in resolved:
        click.echo(f"[chimera] loading {script_id}")
        await session.load_script(source)

    try:
        if interactive:
            click.echo("[chimera] interactive mode — each line is eval'd in the agent.")
            click.echo("[chimera] type 'quit' to detach.")
            while True:
                try:
                    line = await _aio.to_thread(input, "frida> ")
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    continue
                if line.strip() in {"quit", "exit", ".q"}:
                    break
                try:
                    result = await session.evaluate(line)
                    click.echo(repr(result))
                except Exception as exc:
                    click.echo(f"[chimera] error: {exc}", err=True)
        else:
            click.echo(f"[chimera] holding session for {duration}s (Ctrl+C to detach)")
            elapsed = 0
            tick = 1
            while elapsed < duration:
                await _aio.sleep(tick)
                elapsed += tick
                if print_messages:
                    for msg in session.drain_messages():
                        click.echo(f"[agent] {msg}")
    except KeyboardInterrupt:
        click.echo("\n[chimera] interrupted")
    finally:
        await adapter.cleanup()
        click.echo("[chimera] detached")
