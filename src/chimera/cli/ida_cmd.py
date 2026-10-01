"""chimera ida — drive a (cached) IDA database: list functions, disassemble,
decompile, or run an arbitrary IDC/IDAPython script. The IDB is built once and
reused, so repeated queries are fast."""
from __future__ import annotations

import asyncio
import json as _json

import click

from chimera.cli._root import main


@main.command("ida")
@click.argument("path", type=click.Path(exists=True))
@click.option("--mode", type=click.Choice(["functions", "disasm", "decompile", "script"]),
              default="functions", help="What to extract from the IDB (default: functions).")
@click.option("--addr", "address", default=None, help="Function address (disasm/decompile).")
@click.option("--script", "script", type=click.Path(exists=True), default=None,
              help="IDC/IDAPython file to run against the cached IDB (mode=script).")
@click.option("--json", "as_json", is_flag=True)
def ida(path: str, mode: str, address: str | None, script: str | None, as_json: bool):
    """IDA-backed analysis of PATH (PE/ELF/Mach-O) with a persistent IDB cache."""
    from chimera.adapters.ida import IdaAdapter

    a = IdaAdapter()
    if not a.is_available():
        raise click.ClickException(
            "IDA not found — install IDA Pro and set IDA_PATH (or put idat64 on PATH).")
    opts: dict = {"mode": mode}
    if address:
        opts["address"] = address
    if script:
        opts["script"] = script
    r = asyncio.run(a.analyze(path, opts))
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    if not r.get("ok"):
        msg = r.get("error", "ida failed")
        if r.get("hint"):
            msg += f" — {r['hint']}"
        raise click.ClickException(msg)
    if mode == "functions":
        click.echo(f"[chimera] IDA recovered {r['count']} functions")
        for fn in r["functions"]:
            click.echo(f"  {fn['addr']}  {fn['size']:>6}  {fn['name']}")
    elif mode == "disasm":
        click.echo(f"[chimera] disasm {r['address']} ({r['lines']} lines):")
        click.echo(r["disasm"])
    elif mode == "decompile":
        click.echo(f"[chimera] decompile {r['address']} via {r['backend']} ({r['lines']} lines):")
        click.echo(r["code"])
    else:
        click.echo(r["output"])
