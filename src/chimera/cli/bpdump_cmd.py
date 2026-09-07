"""chimera bp-dump — launch a program under ptrace, break at an address, and
dump registers + pointer memory when it's hit.

The no-sudo way to read a value a program computes at runtime (a derived key, a
decrypted buffer) at the exact instruction it's live: because chimera launches
the target, ptrace is permitted even under yama ptrace_scope=1. Backed by
chimera.dynamic.ptrace_bp. x86-64 Linux only.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("bp-dump")
@click.argument("argv", nargs=-1, required=True)
@click.option("--addr", default=None,
              help="Breakpoint address (hex, e.g. 0x401136).")
@click.option("--signature", default=None,
              help="Hex byte pattern to locate at runtime; break at found+delta "
                   "(ASLR-proof). Use instead of --addr.")
@click.option("--delta", default="0",
              help="Signed offset (hex ok) added to the signature's address.")
@click.option("--dump", "dumps", multiple=True,
              help="reg:len — read len bytes from the address in reg at the hit "
                   "(e.g. rdi:32). Repeatable.")
@click.option("--max-hits", type=int, default=1, help="Stop after N hits.")
@click.option("--timeout", type=float, default=30, help="Kill after N seconds.")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as JSON.")
def bp_dump(argv, addr, signature, delta, dumps, max_hits, timeout, as_json):
    """Run ARGV..., break at --addr (or --signature/--delta), dump regs on hit."""
    from chimera.dynamic.ptrace_bp import PtraceUnsupported, run_with_breakpoints

    if not addr and not signature:
        raise click.ClickException("give --addr or --signature")
    parsed = []
    for d in dumps:
        reg, _, ln = d.partition(":")
        parsed.append([reg.strip(), int(ln or 16)])
    if signature:
        bp = {"signature": signature, "delta": int(delta, 0), "dumps": parsed}
    else:
        bp = {"addr": int(addr, 16), "dumps": parsed}
    try:
        result = run_with_breakpoints(list(argv), [bp],
                                      timeout=timeout, max_hits=max_hits)
    except PtraceUnsupported as exc:
        raise click.ClickException(str(exc))

    if as_json:
        click.echo(_json.dumps(result, indent=2, default=hex))
        return
    if result.get("error"):
        raise click.ClickException(result["error"])
    if not result["hits"]:
        click.echo(f"[chimera] breakpoint never hit "
                   f"(exit={result['exit_code']}, timed_out={result['timed_out']})")
        return
    for h in result["hits"]:
        click.echo(f"[chimera] hit {h['addr']:#x} (tid {h['tid']})")
        regs = h.get("registers", {})
        for reg, _ln in parsed:
            rv = regs.get(reg)
            mem = h["dumps"].get(reg)
            line = f"    {reg} = {rv:#x}" if isinstance(rv, int) else f"    {reg}"
            if mem:
                line += f"  [{reg}] -> {mem}"
            click.echo(line)
