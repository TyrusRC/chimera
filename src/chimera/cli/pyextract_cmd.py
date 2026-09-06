"""chimera pyextract — recover the embedded Python from a PyInstaller EXE."""

from __future__ import annotations

from pathlib import Path

import click

from chimera.cli._root import main


@main.command("pyextract")
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <exe>_extracted).")
def pyextract(path: str, out_dir: str | None):
    """Extract a PyInstaller-frozen EXE's scripts, modules, and PYZ into .pyc.

    Read-only; the target is never executed. Feed the recovered .pyc to a
    decompiler or `python -m dis` for the source.
    """
    from chimera.unpacking.pyinstaller import extract_pyinstaller, is_pyinstaller

    data = Path(path).read_bytes()
    if not is_pyinstaller(data):
        raise click.ClickException(
            "not a PyInstaller archive (no CArchive cookie found).")

    out = Path(out_dir) if out_dir else Path(path).with_name(Path(path).stem + "_extracted")
    r = extract_pyinstaller(path, out)
    if not r.ok:
        raise click.ClickException(r.error or "extraction failed")

    click.echo(f"[chimera] PyInstaller archive → Python {r.python_version}")
    if r.note:
        click.echo(f"  note: {r.note}")
    click.echo(f"  entry-point scripts ({len(r.entry_points)}): "
               + ", ".join(r.entry_points))
    click.echo(f"  app modules: {len(r.modules)}   PYZ modules: {len(r.pyz_modules)}")
    click.echo(f"  extracted → {out}")
    # Point the analyst at the interesting file: the non-bootstrap entry point.
    app = [e for e in r.entry_points if not e.startswith(("pyi", "pyiboot"))]
    if app:
        click.echo(f"  start here: {out}/{app[0]}.pyc")
