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
              help="Method name to hook (repeatable). Hook the inner "
                   "comparator/key-builder, not the outer validator — "
                   "hooking the entry validator perturbs the code path.")
@click.option("--input", "stdin_line", default="",
              help="Line fed to the assembly's stdin (e.g. a candidate key).")
@click.option("--work-dir", type=click.Path(), default=None,
              help="Working directory (default: a temp dir).")
@click.option("--timeout", type=int, default=180)
def dotnet_trace(path: str, methods: tuple[str, ...], stdin_line: str,
                 work_dir: str | None, timeout: int):
    """Run a Windows .NET assembly on Linux and trace named methods.

    Runs the assembly under the installed .NET Core runtime via a
    runtimeconfig shim, installs Harmony hooks on the requested methods, and
    reports every byte[]/string they receive or return. Because Harmony
    detours JIT'd native code rather than on-disk IL, this sees through the
    VM-protection / anti-tamper layers that defeat static devirtualization —
    a hooked comparator hands you the value it is comparing against.
    """
    from chimera.dotnet.tracer import trace, dotnet_available

    if not dotnet_available():
        raise click.ClickException(
            "the .NET SDK is not installed — `dotnet` not found on PATH. "
            "Install it, and (for hooking) it will build the tracer harness "
            "on first run.")

    wd = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="chimera_dotnet_"))
    result = trace(Path(path), list(methods), stdin_line=stdin_line,
                   work_dir=wd, timeout=timeout)

    if not result.available:
        raise click.ClickException(result.error or "tracer unavailable")

    click.echo(f"Traced {Path(path).name}  "
               f"(input={stdin_line!r}, hooks={result.hooks_installed})")
    if result.error:
        click.echo(f"  note: {result.error}")

    byte_vals = result.byte_values()
    strings = result.strings_seen()
    if not byte_vals and not strings:
        click.echo("  no byte[]/string values captured — check the method "
                   "names, or the code path may not have reached them.")
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
