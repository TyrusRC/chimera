"""chimera dispatch-tables — find arrays of code pointers (a state-handler or
jump table) in a PE and validate each entry against the real function starts.

A generated state machine / VM interpreter dispatches through such a table; its
length is the state/handler count, which is otherwise invisible when a
disassembler's call-graph walk is defeated (ILT-heavy /INCREMENTAL PE). Backed
by chimera.parsers.pe_dispatch.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("dispatch-tables")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit candidates as JSON.")
@click.option("--limit", type=int, default=20, help="Show at most N tables.")
def dispatch_tables(path: str, as_json: bool, limit: int):
    """List candidate dispatch/jump tables in PE `path`, largest first."""
    from chimera.parsers.pe_dispatch import find_dispatch_tables

    tables = find_dispatch_tables(path)
    if as_json:
        click.echo(_json.dumps(tables, indent=2))
        return
    if not tables:
        click.echo("[chimera] no pointer-array dispatch tables found "
                   "(needs a PE with a .pdata function table).")
        return
    click.echo(f"[chimera] {len(tables)} candidate table(s):")
    for t in tables[:limit]:
        conf = " [pdata-backed]" if t.get("pdata_backed") else ""
        click.echo(f"  {t['section']:8} base={t['base_va']:#x}  "
                   f"count={t['count']}  {t['kind']}/{t['ptr_size']}B{conf}")
