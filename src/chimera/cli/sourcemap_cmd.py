"""chimera sourcemap — recover original sources from a JS bundle / .map."""
from __future__ import annotations

import json as _json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("sourcemap")
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output dir for recovered sources (default: <name>_src).")
@click.option("--json", "as_json", is_flag=True, help="Print the recovery result as JSON (no write).")
def sourcemap(path: str, out_dir: str | None, as_json: bool):
    """Recover the original source tree from PATH (a .map or a bundle with a sourceMappingURL)."""
    from chimera.unpacking.sourcemap import recover_sources, write_sources

    r = recover_sources(path)
    if as_json:
        click.echo(_json.dumps({k: v for k, v in r.items() if k != "files"}
                               | {"file_paths": sorted(r.get("files", {}))}, indent=2))
        return
    if not r.get("ok"):
        raise click.ClickException(r.get("error", "source map recovery failed"))
    dest = out_dir or (str(Path(path).with_suffix("")) + "_src")
    written = write_sources(r, dest)
    click.echo(f"[chimera] recovered {r['count']} source(s) → {dest}")
    if r.get("missing_content"):
        click.echo(f"  ({len(r['missing_content'])} source(s) had no embedded content)")
    for w in written[:20]:
        click.echo(f"  {w}")
