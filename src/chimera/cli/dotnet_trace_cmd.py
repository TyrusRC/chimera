"""chimera.cli — dotnet-trace (run + hook a .NET assembly on Linux)."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


@main.command("dotnet-trace")
@click.argument("path", type=click.Path(exists=True))
@click.option("--method", "methods", multiple=True, required=True,
              help="Method to hook (repeatable). A bare name hooks that "
                   "method in the target; TYPE::NAME (e.g. "
                   "System.String::op_Equality) hooks a BCL method. Hook the "
                   "inner comparator / VM memory primitive, not the outer "
                   "validator — hooking the entry validator perturbs the path.")
@click.option("--input", "inputs", multiple=True,
              help="A line fed to the assembly's stdin (repeatable, in order) "
                   "— use one per menu step to drive a menu-loop program to "
                   "its key prompt.")
@click.option("--neutralize-pinvoke", is_flag=True,
              help="Stub kernel32/ntdll so a Windows-only binary runs on "
                   "Linux; this also blanks its anti-debug imports "
                   "(CheckRemoteDebuggerPresent, NtQueryInformationProcess).")
@click.option("--work-dir", type=click.Path(), default=None,
              help="Working directory (default: a temp dir).")
@click.option("--timeout", type=int, default=180)
def dotnet_trace(path: str, methods: tuple[str, ...], inputs: tuple[str, ...],
                 neutralize_pinvoke: bool, work_dir: str | None, timeout: int):
    """Run a Windows .NET assembly on Linux and trace named methods.

    Runs the assembly under the installed .NET Core runtime via a
    runtimeconfig shim, installs Harmony hooks on the requested methods, and
    reports the byte[]/string values they see plus any int/char stream they
    move. Because Harmony detours JIT'd native code rather than on-disk IL,
    this sees through VM-protection / anti-tamper layers that defeat static
    devirtualization — a hooked comparator (or a VM memory-read primitive)
    hands you the value it is checking against.
    """
    from chimera.dotnet.tracer import trace, dotnet_available

    if not dotnet_available():
        raise click.ClickException(
            "the .NET SDK is not installed — `dotnet` not found on PATH. "
            "Install it, and (for hooking) it will build the tracer harness "
            "on first run.")

    wd = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="chimera_dotnet_"))
    result = trace(Path(path), list(methods),
                   stdin_lines=list(inputs) if inputs else None,
                   neutralize_pinvoke=neutralize_pinvoke,
                   work_dir=wd, timeout=timeout)

    if not result.available:
        raise click.ClickException(result.error or "tracer unavailable")

    click.echo(f"Traced {Path(path).name}  "
               f"(inputs={list(inputs)}, hooks={result.hooks_installed})")
    if result.error:
        click.echo(f"  note: {result.error}")

    byte_vals = result.byte_values()
    strings = result.strings_seen()
    streams = result.numeric_streams()
    if not byte_vals and not strings and not streams:
        click.echo("  no values captured — check the method names, or the "
                   "code path may not have reached them.")
        return

    if byte_vals:
        click.echo("\n  byte[] values (a comparator's argument is your input; "
                   "its return-side or a builder's value is the target):")
        for method, ascii_, hex_ in byte_vals:
            click.echo(f"    {method}: {ascii_!r}")
            click.echo(f"        hex {hex_}")
    if strings:
        click.echo("\n  string values:")
        for method, value in strings:
            click.echo(f"    {method}: {value!r}")
    if streams:
        click.echo("\n  int/char streams (a VM moves the bytes it compares "
                   "through here — read the ASCII for the target):")
        for method, chans in streams.items():
            for chan in ("return", "args"):
                values = chans.get(chan) or []
                if values:
                    click.echo(f"    {method} [{chan}]: "
                               f"{result.reconstruct_ascii(values)!r}")
