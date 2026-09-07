"""chimera aeskeys — recover AES keys by finding their expanded key schedule in
a file (memory dump / core / blob) or a live process's memory.

For a key computed at runtime behind obfuscation — never a literal in the binary
— dump or freeze the process and scan: the schedule is self-checking, so the key
falls out. Backed by chimera.aes_keyfind.
"""
from __future__ import annotations

import json as _json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("aeskeys")
@click.argument("target")
@click.option("--pid", is_flag=True, help="Treat TARGET as a PID, not a file path.")
@click.option("--bits", default="128,192,256",
              help="Comma-separated key sizes to look for (default all).")
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON.")
def aeskeys(target: str, pid: bool, bits: str, as_json: bool):
    """Scan TARGET (a file, or a PID with --pid) for AES key schedules."""
    from chimera.aes_keyfind import find_in_file, find_in_pid

    want = tuple(int(b) for b in bits.split(",") if b.strip())
    if pid or (target.isdigit() and not Path(target).exists()):
        hits = find_in_pid(int(target))
        hits = [h for h in hits if h["bits"] in want]
        where = f"pid {target}"
    else:
        if not Path(target).exists():
            raise click.ClickException(f"file not found: {target}")
        hits = find_in_file(target, bits=want)
        where = target

    if as_json:
        click.echo(_json.dumps(hits, indent=2))
        return
    if not hits:
        click.echo(f"[chimera] no AES key schedules found in {where}")
        return
    click.echo(f"[chimera] {len(hits)} AES key(s) in {where}:")
    for h in hits:
        click.echo(f"  AES-{h['bits']} @ {h['address']:#x}  key={h['key']}"
                   f"  iv?={h['iv_candidate']}")
