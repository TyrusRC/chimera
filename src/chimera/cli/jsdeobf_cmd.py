"""chimera.cli — js-deobf: deobfuscate a standalone .js/.html."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("js-deobf")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <name>_deobf next to the input).")
@click.option("--no-prettier", "prettier", is_flag=True, default=True,
              flag_value=False, help="Skip prettier; use the built-in line-splitter.")
def js_deobf(path: str, out_dir: str | None, prettier: bool):
    """Deobfuscate standalone JavaScript / HTML (webcrack + prettier).

    Extracts inline <script> bodies from HTML, runs webcrack (unflatten /
    unminify / inline the string array), then line-splits the result so it is
    greppable. Writes cleaned .js files and prints their paths + sizes — the
    (often multi-MB) content is left on disk, not dumped. Needs node + webcrack
    (`npm i -g webcrack`, or reachable via npx).
    """
    from chimera.unpacking.js_deobf import deobfuscate
    r = deobfuscate(path, out_dir=out_dir, prettier=prettier)
    if not r.get("available"):
        raise click.ClickException(r.get("error", "webcrack unavailable"))
    if r.get("error"):
        raise click.ClickException(r["error"])
    click.echo(f"[js-deobf] html={r['is_html']} scripts={r['scripts_found']} "
               f"formatter={r['formatter']}")
    for e in r.get("errors", []):
        click.echo(f"  war: {e}", err=True)
    for f in r["output_files"]:
        click.echo(f"  {f['size']:>9} B  {f['path']}")
    click.echo(f"  {r['note']}")
