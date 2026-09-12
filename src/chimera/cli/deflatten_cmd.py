"""chimera deflatten — recover the CFG of a computed-goto / MBA-obfuscated function.

Flattening obfuscators end every block in a computed `jmp rax`; a linear
disassembler sees one opaque block. This resolves the real edges by emulating
each block's footer expression (whole image mapped). Backed by
chimera.parsers.cfg_deflatten.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("deflatten")
@click.argument("path", type=click.Path(exists=True))
@click.option("--entry", required=True, help="Function entry address (0x…).")
@click.option("--max-blocks", type=int, default=4000)
@click.option("--dot", "dot_out", type=click.Path(), default=None,
              help="Write the Graphviz DOT to this file.")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def deflatten(path: str, entry: str, max_blocks: int, dot_out: str | None, as_json: bool):
    """Recover and print the CFG of the flattened function at --entry."""
    from chimera.parsers.cfg_deflatten import recover_cfg

    r = recover_cfg(path, entry, max_blocks=max_blocks)
    if not r.get("available"):
        raise click.ClickException(r.get("error", "recover_cfg failed"))
    if dot_out:
        with open(dot_out, "w") as fh:
            fh.write(r["dot"])
    if as_json:
        r_copy = dict(r)
        r_copy.pop("dot", None)
        click.echo(_json.dumps(r_copy, indent=2))
        return
    click.echo(f"[chimera] CFG of {r['entry']}: {r['block_count']} blocks, "
               f"{r['edge_count']} edges, {r['unresolved_jmpreg']} unresolved jmp reg")
    if dot_out:
        click.echo(f"  DOT written to {dot_out}")
    for b in r["blocks"][:20]:
        click.echo(f"  {b['start']:>12} {b['term']:<7} -> "
                   f"{', '.join(b['successors']) or '(none)'}")
    if len(r["blocks"]) > 20:
        click.echo(f"  … {len(r['blocks']) - 20} more blocks")
