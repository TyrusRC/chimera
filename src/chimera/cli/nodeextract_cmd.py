"""chimera node-extract — recover the embedded JS from a Node compiled binary."""

from __future__ import annotations


import click

from chimera.cli._root import main


@main.command("node-extract")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <name>_node beside the input).")
def node_extract(path: str, out_dir: str | None):
    """Extract the embedded JavaScript from a nexe / Node-SEA / pkg executable.

    A Node app shipped as one native binary (a 50MB `.exe` that just "asks for
    a flag") hides its JS bundle in an appended/injected blob — no need to
    decompile the node runtime. Read-only; the target is never executed. Feed
    the recovered .js to `js-deobf`.
    """
    from chimera.unpacking.nodejs import extract_node_js

    r = extract_node_js(path, out_dir)
    if not r.ok:
        msg = r.error or "extraction failed"
        if r.note:
            msg = f"{msg}\n  note: {r.note}"
        raise click.ClickException(msg)

    click.echo(f"[chimera] Node compiled binary → {r.kind}")
    if r.sea_flags is not None:
        click.echo(f"  SEA flags: {r.sea_flags:#06x}")
    if r.resource_size:
        extracted = f"{len(r.resource_files)} file(s) extracted" if r.resource_files else "raw"
        click.echo(f"  resource blob: {r.resource_size} B ({extracted})")
    if r.note:
        click.echo(f"  note: {r.note}")
    click.echo(f"  {r.js_size} B  {r.out_file}")
    for rf in r.resource_files:
        click.echo(f"  app file: {rf}")
    # The app code (in the resource VFS) is the interesting target when present.
    start = r.resource_files[0] if r.resource_files else r.out_file
    click.echo(f"  next: chimera js-deobf {start}")
