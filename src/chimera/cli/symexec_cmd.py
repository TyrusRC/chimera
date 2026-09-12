"""chimera symexec — angr symbolic execution to find a winning input."""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("symexec")
@click.argument("path", type=click.Path(exists=True))
@click.option("--find", default=None, help="Win address (hex, e.g. 0x401337).")
@click.option("--find-stdout", "find_stdout", default=None,
              help="String the winning state must print (alternative to --find).")
@click.option("--avoid", multiple=True, help="Failure address to prune (hex, repeatable).")
@click.option("--avoid-stdout", "avoid_stdout", default=None,
              help="String a failing state prints (e.g. 'Wrong').")
@click.option("--stdin-len", "stdin_len", type=int, default=None,
              help="Symbolic stdin length in bytes.")
@click.option("--sym-arg", "sym_argv", multiple=True, type=int,
              help="Byte-length of a symbolic argv entry (repeatable).")
@click.option("--timeout", type=int, default=120)
@click.option("--json", "as_json", is_flag=True)
def symexec(path, find, find_stdout, avoid, avoid_stdout, stdin_len, sym_argv,
            timeout, as_json):
    """Find the input that drives PATH to --find / --find-stdout."""
    from chimera.dynamic.symexec import solve_input, angr_available
    if not angr_available():
        raise click.ClickException("angr not installed — pip install angr")
    if not find and not find_stdout:
        raise click.ClickException("give a target: --find <addr> or --find-stdout <str>")
    r = solve_input(path, find=find, find_stdout=find_stdout, avoid=list(avoid) or None,
                    avoid_stdout=avoid_stdout, stdin_len=stdin_len,
                    sym_argv=list(sym_argv) or None, timeout_s=timeout)
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    if not r.get("ok"):
        raise click.ClickException(r.get("error", "symexec failed"))
    click.echo(f"[chimera] symexec reached {r['target']}:")
    if "stdin" in r:
        click.echo(f"  stdin = {r['stdin']['ascii']!r}  ({r['stdin']['hex']})")
    for a in r.get("argv", []):
        click.echo(f"  {a['name']} = {a['ascii']!r}  ({a['hex']})")
    if r.get("note"):
        click.echo(f"  note: {r['note']}")
