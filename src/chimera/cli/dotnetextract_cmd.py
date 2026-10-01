"""chimera dotnet-extract — carve the files out of a .NET single-file app."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("dotnet-extract")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <name>_bundle beside the input).")
def dotnet_extract(path: str, out_dir: str | None):
    """Extract the bundle from a .NET single-file (self-contained) executable.

    `dotnet publish -p:PublishSingleFile=true` ships the managed assembly, the
    whole CoreCLR runtime and every framework DLL in ONE native binary (a large
    `.exe` that just "asks for a flag") — decompiling the host wastes a full
    Ghidra pass and never reaches the app. This carves every file back out and
    points at the recovered app assembly. Read-only; the target is never run.
    Feed the main assembly to `chimera analyze`.
    """
    from chimera.unpacking.dotnet_bundle import extract_bundle

    r = extract_bundle(path, out_dir)
    if not r.ok:
        raise click.ClickException(r.error or "extraction failed")

    click.echo(f"[chimera] .NET single-file bundle v{r.major_version}.{r.minor_version} "
               f"(id {r.bundle_id})")
    click.echo(f"  {r.file_count} file(s) → {r.out_dir}")
    if r.deps_json:
        click.echo(f"  deps: {r.deps_json}")
    if r.main_assembly:
        click.echo(f"  app assembly: {r.main_assembly}")
        click.echo(f"  next: chimera analyze {r.main_assembly}")
