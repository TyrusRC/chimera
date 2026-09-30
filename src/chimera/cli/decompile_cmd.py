"""chimera decompile — decompile one native function to C (r2ghidra pdg → pdc)."""
from __future__ import annotations

import asyncio
import json as _json

import click

from chimera.cli._root import main


@main.command("decompile")
@click.argument("path", type=click.Path(exists=True))
@click.option("--addr", "address", required=True, help="Function address (0x…).")
@click.option("--decompiler", type=click.Choice(["pdg", "pdc", "ida"]), default=None,
              help="Force a backend (default: r2ghidra pdg, then pdc; 'ida' = Hex-Rays).")
@click.option("--json", "as_json", is_flag=True)
def decompile(path: str, address: str, decompiler: str | None, as_json: bool):
    """Decompile the function at --addr in PATH to C."""
    if decompiler == "ida":
        from chimera.adapters.ida import IdaAdapter

        a = IdaAdapter()
        if not a.is_available():
            raise click.ClickException("IDA not found — install IDA Pro and set IDA_PATH.")
        r = asyncio.run(a.analyze(path, {"mode": "decompile", "address": address}))
    else:
        from chimera.adapters.radare2 import Radare2Adapter

        a = Radare2Adapter()
        if not a.is_available():
            raise click.ClickException("radare2 not found on PATH.")
        r = asyncio.run(a.analyze(path, {"mode": "decompile", "address": address,
                                         "decompiler": decompiler}))
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    if not r.get("ok"):
        msg = r.get("error", "decompile failed")
        if r.get("hint"):
            msg += f" — {r['hint']}"
        raise click.ClickException(msg)
    click.echo(f"[chimera] decompile {r['address']} via {r['backend']} ({r['lines']} lines):")
    click.echo(r["code"])
