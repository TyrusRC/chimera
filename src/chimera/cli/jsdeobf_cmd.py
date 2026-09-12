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
@click.option("--resolve", "resolve", default=None, metavar="NAME[IDX]",
              help="Statically resolve one element of a const array literal "
                   "(e.g. TABLE[12]) across the collected sources — no node/webcrack.")
def js_deobf(path: str, out_dir: str | None, prettier: bool, resolve: str | None):
    """Deobfuscate standalone JavaScript / HTML (webcrack + prettier).

    Follows the web module graph from the entry — inline <script> bodies plus
    every local external <script src> / ES-imported file — runs webcrack
    (unflatten / unminify / inline the string array), then line-splits the
    result so it is greppable. Writes cleaned .js files and prints their paths +
    sizes — the (often multi-MB) content is left on disk, not dumped. Needs
    node + webcrack (`npm i -g webcrack`, or reachable via npx).

    With --resolve NAME[IDX] it instead statically reads that array element (no
    node needed) — the "indexed table -> flag" web-CTF pattern.
    """
    from chimera.unpacking.js_deobf import deobfuscate
    r = deobfuscate(path, out_dir=out_dir, prettier=prettier, resolve=resolve)
    if not r.get("available"):
        raise click.ClickException(r.get("error", "webcrack unavailable"))
    if resolve is not None:
        res = r.get("resolved", {})
        if res.get("error"):
            raise click.ClickException(f"{res['expr']}: {res['error']}")
        val = res.get("value")
        if val is None:
            raise click.ClickException(f"{res['expr']}: not a resolvable const array element")
        click.echo(val)
        return
    if r.get("error"):
        raise click.ClickException(r["error"])
    click.echo(f"[js-deobf] html={r['is_html']} scripts={r['scripts_found']} "
               f"formatter={r['formatter']}")
    for m in r.get("module_graph", []):
        click.echo(f"  module: {m}")
    for s in r.get("skipped_refs", []):
        click.echo(f"  skipped (remote/bare): {s}", err=True)
    for e in r.get("errors", []):
        click.echo(f"  war: {e}", err=True)
    for f in r["output_files"]:
        click.echo(f"  {f['size']:>9} B  {f['path']}")
    click.echo(f"  {r['note']}")
