"""chimera polyglot — find embedded formats at any offset; carve one out."""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("polyglot")
@click.argument("path", type=click.Path(exists=True))
@click.option("--extract", "extract_off", type=int, default=None,
              help="Carve from this byte offset instead of listing.")
@click.option("-o", "--out", "out_path", type=click.Path(), default=None,
              help="Output file for --extract (default: <name>.carved_<off>).")
@click.option("--size", type=int, default=None, help="Bytes to carve (default: to EOF).")
@click.option("--json", "as_json", is_flag=True)
def polyglot(path: str, extract_off: int | None, out_path: str | None,
             size: int | None, as_json: bool):
    """List embedded formats in PATH, or --extract <offset> to carve a region out."""
    from chimera.unpacking.polyglot import carve, scan

    if extract_off is not None:
        dest = out_path or f"{path}.carved_{extract_off}"
        n = carve(path, extract_off, dest, size)
        click.echo(f"[chimera] carved {n} bytes @ 0x{extract_off:x} → {dest}")
        return

    hits = scan(path)
    if as_json:
        click.echo(_json.dumps(hits, indent=2))
        return
    if not hits:
        click.echo("no embedded formats found")
        return
    click.echo(f"[chimera] {len(hits)} embedded format(s) in {path}:")
    for h in hits:
        line = f"  0x{h['offset']:08x}  {h['format']}"
        if h.get("size"):
            line += f"  (~{h['size']} B)"
        click.echo(line)
        for s in h.get("slices", []):
            click.echo(f"      slice cputype={s['cputype']} subtype={s['subtype']} "
                       f"@ {s['offset']} ({s['size']} B)")
