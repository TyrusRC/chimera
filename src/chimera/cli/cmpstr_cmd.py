"""chimera cmp-string — recover a hidden string from a byte-comparison cascade.

When a password / serial / key-sequence check is compiled as an unrolled
`if(buf[0]=='L') if(buf[1]=='L') ...`, the expected value exists only as `cmp`
immediates and never appears in `strings`/FLOSS output. This reads those
immediates back in order. Backed by chimera.parsers.cmp_strings.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("cmp-string")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--addr", "addr", required=True, metavar="VA",
              help="Function virtual address to scan (hex, e.g. 0x004024e0).")
@click.option("--max-bytes", type=int, default=2048, show_default=True,
              help="Bytes of code to disassemble from the VA.")
@click.option("--min-run", type=int, default=4, show_default=True,
              help="Minimum characters for a reported candidate.")
@click.option("--gap", type=int, default=128, show_default=True,
              help="Max byte gap between compares before a new candidate starts.")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def cmp_string(path: str, addr: str, max_bytes: int, min_run: int, gap: int, as_json: bool):
    """Reconstruct the string implied by a cmp-immediate cascade at --addr."""
    from chimera.parsers.cmp_strings import recover_compare_string
    r = recover_compare_string(path, int(addr, 16), max_bytes=max_bytes,
                               min_run=min_run, gap=gap)
    if as_json:
        click.echo(_json.dumps(r, indent=2))
        return
    if r.get("error"):
        raise click.ClickException(r["error"])
    cands = r["candidates"]
    if not cands:
        click.echo(f"[cmp-string] no cascade of >= {min_run} chars at {addr} "
                   f"({r['arch']}). Try a larger --max-bytes/--gap or check the VA.")
        return
    click.echo(f"[cmp-string] {len(cands)} candidate(s) at {addr} ({r['arch']}):")
    for c in cands:
        click.echo(f"  {c['count']:>3}  {c['string']!r}  @ {c['start_va']}")


@main.command("data-bytes")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--addr", "addr", required=True, metavar="VA",
              help="Function VA whose inline immediate stores build the array (hex).")
@click.option("--max-bytes", type=int, default=4096, show_default=True,
              help="Bytes of code to disassemble from the VA.")
@click.option("--gadget-target", "gadget_target", default=None, metavar="BYTE",
              help="Invert an additive gadget: input[i]=(target-data[i])&0xff, "
                   "e.g. 0xC3 for a `ret` (darn_mice-style byte=data[i]+input[i] exec).")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def data_bytes(path: str, addr: str, max_bytes: int, gadget_target: str | None, as_json: bool):
    """Reassemble a byte array built by inline `mov [buf+i], imm` stores at --addr."""
    from chimera.parsers.cmp_strings import recover_data_bytes
    gt = None
    if gadget_target is not None:
        gt = int(gadget_target, 16) if gadget_target.lower().startswith("0x") else int(gadget_target)
    r = recover_data_bytes(path, int(addr, 16), max_bytes=max_bytes, gadget_target=gt)
    if as_json:
        click.echo(_json.dumps(r, indent=2))
        return
    if r.get("error"):
        raise click.ClickException(r["error"])
    click.echo(f"[data-bytes] {r['byte_count']} bytes at {addr} ({r['arch']}): {r['hex']}")
    if "derived_input_hex" in r:
        click.echo(f"  derived input (target {r['gadget_target']}): {r['derived_input_hex']}")
        if "derived_input_ascii" in r:
            click.echo(f"  derived input (ascii): {r['derived_input_ascii']!r}")
