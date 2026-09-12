"""chimera.cli — core: triage an ELF process core dump."""

from __future__ import annotations

import json

import click

from chimera.cli._root import main


@main.command("core")
@click.argument("corefile", type=click.Path(exists=True, dir_okay=False))
@click.option("--addr", default=None, help="Resolve a virtual address to module+offset (hex).")
@click.option("--search", "search_hex", default=None, help="Find these hex bytes in memory.")
@click.option("--dump", "dump_spec", default=None, help="Hexdump memory as ADDR:LEN (hex:dec).")
def core(corefile: str, addr: str | None, search_hex: str | None, dump_spec: str | None):
    """Triage an ELF core dump: registers, module maps, address→module, memory.

    Fills the gap Volatility (`memory`) doesn't — a userspace process core. Shows
    the crashing thread's registers and which module rip / the stack return fall
    in, and lets you resolve an address, search memory, or dump a region.
    """
    from chimera.parsers.coredump import CoreDump
    try:
        c = CoreDump(corefile)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    try:
        if addr:
            a = int(addr, 16)
            r = c.address_to_module(a)
            click.echo(f"{addr}: {r[0]}+{hex(r[1])}" if r else f"{addr}: <unmapped>")
            return
        if search_hex:
            hits = c.search(bytes.fromhex(search_hex))
            click.echo(f"{len(hits)} hit(s): " + ", ".join(hex(h) for h in hits[:32]))
            return
        if dump_spec:
            addr_s, _, len_s = dump_spec.partition(":")
            data = c.read(int(addr_s, 16), int(len_s or "64"))
            if data is None:
                raise click.ClickException("address not in a mapped, file-backed region")
            click.echo(data.hex())
            return
        click.echo(json.dumps(c.triage(), indent=2))
    finally:
        c.close()
