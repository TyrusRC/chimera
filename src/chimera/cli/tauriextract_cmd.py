"""chimera tauri-extract — carve the embedded web frontend from a Tauri app."""

from __future__ import annotations


import click

from chimera.cli._root import main


@main.command("tauri-extract")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <name>_tauri_assets beside the input).")
def tauri_extract(path: str, out_dir: str | None):
    """Carve the embedded HTML/JS/CSS/images from a Tauri (Rust) binary.

    Tauri bundles its UI into the Rust executable (EmbeddedAssets). This finds
    that table with no hardcoded offsets, decompresses each asset (brotli/zstd),
    and writes them out, then flags whether the real logic is likely NOT in the
    static assets (an embedded V8 isolate that runtime-decrypts its script).
    Read-only; the target is never executed. Feed recovered .js/.html to
    `js-deobf`. (ELF carving is implemented; PE/Mach-O Tauri is detected only.)
    """
    from chimera.unpacking.tauri import extract_tauri

    r = extract_tauri(path, out_dir)
    if not r.ok:
        raise click.ClickException(r.error or "not a Tauri binary")

    ver = f" {r.tauri_version}" if r.tauri_version else ""
    click.echo(f"[chimera] Tauri{ver} app")
    if r.embedded_v8:
        click.echo(f"  embedded V8: {r.embedded_v8}")
    if r.assets:
        click.echo(f"  {len(r.assets)} asset(s) → {r.out_dir}")
        for a in r.assets:
            click.echo(f"    {a.name}  [{a.codec}]  {a.blob_size} B → {a.out_size} B  {a.out_path}")
    if r.note:
        click.echo(f"  note: {r.note}")
    js = [a for a in r.assets if a.name.endswith((".js", ".html"))]
    if js:
        click.echo(f"  next: chimera js-deobf {js[0].out_path}")
