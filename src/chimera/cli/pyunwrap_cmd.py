"""chimera pyunwrap — peel a layered/marshalled Python blob, statically."""

from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


def _echo_tree(node, depth: int = 0) -> None:
    """Print the layer tree as an indented outline."""
    pad = "  " * depth
    if node.co_names is not None:                          # a code node
        click.echo(f"{pad}[code] {node.name}  "
                   f"names={list(node.co_names)}")
        for s in (node.co_consts_summary or []):
            click.echo(f"{pad}    const {s}")
    else:
        detail = f"  {node.detail}" if node.detail else ""
        click.echo(f"{pad}[{node.kind}]{detail}")
    for child in node.children:
        _echo_tree(child, depth + 1)


@main.command("pyunwrap")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True,
              help="Emit the layer tree as JSON.")
@click.option("--disasm", is_flag=True,
              help="Also disassemble each recovered code node (uses xdis if present).")
def pyunwrap(path: str, as_json: bool, disasm: bool):
    """Recursively peel marshal/zlib/base64/base85/bz2/lzma layers from a file.

    Read-only; the target is never imported or executed. Dumps the
    version-independent co_names / co_consts tree of every code object found —
    valid even when the bytecode was compiled for a different Python version.
    """
    from chimera.unpacking.pybytecode import disassemble, unwrap

    result = unwrap(path)
    if result.error and result.root is None:
        raise click.ClickException(result.error)

    if as_json:
        click.echo(_json.dumps(result.to_dict(), indent=2))
        return

    click.echo(f"[chimera] pyunwrap {path}")
    if result.python_version:
        click.echo(f"  compiled for Python {result.python_version}")
    if result.truncated:
        click.echo("  note: output truncated at the size budget (possible zip-bomb)")
    if result.root is not None:
        _echo_tree(result.root)

    if disasm:
        for cn in result.code_nodes():
            click.echo(f"\n# ── disassembly: {cn.name} ──")
            click.echo(disassemble(cn.code_obj))
