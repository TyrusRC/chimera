"""chimera.cli — flutter cmd commands."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# flutter-extract — B(l)utter Dart AOT snapshot extraction
# ----------------------------------------------------------------------


@main.command("flutter-extract")
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", type=click.Path(), required=True,
              help="Output directory for B(l)utter artifacts.")
@click.option("--libapp", "libapp_override", type=click.Path(exists=True),
              default=None,
              help="Explicit path to libapp.so / App binary (skips auto-detect).")
@click.option("--blutter-bin", type=click.Path(exists=True), default=None,
              help="Path to the blutter binary (default: $PATH / $CHIMERA_BLUTTER_BIN).")
def flutter_extract(path: str, out_dir: str, libapp_override: str | None,
                    blutter_bin: str | None):
    """Reverse-engineer Flutter / Dart AOT bundles via B(l)utter.

    PATH is either an unpacked APK directory, an APK file (will be
    auto-unpacked first), or a libapp.so / App binary directly.
    Requires the `blutter` binary on PATH or via --blutter-bin.
    Install from https://github.com/worawit/blutter (MIT).
    """
    from chimera.adapters.blutter_adapter import BlutterAdapter, detect_libapp

    adapter = BlutterAdapter(binary_path=blutter_bin)
    if not adapter.is_available():
        raise click.ClickException(
            "blutter binary not found. Install from "
            "https://github.com/worawit/blutter, put it on PATH, "
            "or pass --blutter-bin / set CHIMERA_BLUTTER_BIN."
        )

    # Resolve the libapp target. If the user passed an APK, we lean on
    # apktool downstream — for now, require either an unpacked dir or
    # an explicit binary.
    target = Path(libapp_override) if libapp_override else None
    if target is None:
        target = detect_libapp(Path(path)) if Path(path).is_dir() else \
                 (Path(path) if Path(path).is_file() else None)
    if target is None or not target.exists():
        raise click.ClickException(
            f"Could not locate libapp.so / App binary under {path!r}. "
            "Unpack the APK first (apktool d) or pass --libapp explicitly."
        )

    click.echo(f"[chimera] blutter: extracting {target.name} → {out_dir}")
    result = adapter.extract(target, out_dir)
    if not result.success:
        click.echo(f"[chimera] blutter FAILED: {result.stderr[:500]}", err=True)
        raise click.exceptions.Exit(3)
    click.echo(f"[chimera] blutter: {result.classes_dumped} classes, "
               f"~{result.methods_dumped} methods written to {out_dir}")
