"""chimera.cli — unpack cmd commands."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# unpack — packer detection + UPX shell-out + protected-binary guidance
# ----------------------------------------------------------------------


@main.command("unpack")
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--packer", "packer_override", type=str, default=None,
              help="Force a specific packer (skip auto-detection).")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output path (default: <binary>.unpacked.<ext>)")
@click.option("--detect-only", is_flag=True,
              help="Run detection and print findings; do not attempt unpacking.")
def unpack(binary: str, packer_override: str | None, out_path: str | None,
           detect_only: bool):
    """Detect a binary's packer and attempt to unpack it.

    \b
    Supported automated paths:
      * UPX (calls `upx -d`)
    Detected, manually-handled (guidance printed):
      * Themida / VMProtect / ASPack / PECompact / MPRESS / Enigma

    Detection uses chimera's bundled YARA packer rules first, then falls
    back to a section-entropy heuristic. Pass --packer to skip detection.
    """
    from chimera.unpacking import (
        UnpackError,
        detect_packer,
        run_unpacker,
        unpacker_for,
    )

    src = Path(binary)
    detection = detect_packer(src)
    click.echo(f"[chimera] detection: packer={detection.packer or '(none)'} "
               f"entropy_sections={detection.high_entropy_sections} "
               f"signals={','.join(detection.signals) or '-'}")
    if detection.suspected_packed:
        # Without this the analyst reads "packer=(none)" as "not packed",
        # when we in fact have structural evidence it is.
        click.echo("[chimera] SUSPECTED PACKED (unattributed) — evidence above; "
                   "no signature matched, so no automated unpacker applies.")
        click.echo("[chimera] (identify it manually, then re-run with "
                   "--packer NAME)")

    if detect_only:
        return

    packer = packer_override or detection.packer
    if not packer:
        click.echo("[chimera] no packer detected; nothing to unpack")
        click.echo("[chimera] (pass --packer NAME to force, "
                   "or --detect-only to see signals)")
        raise click.exceptions.Exit(0)

    unpacker = unpacker_for(packer)
    if unpacker is None:
        click.echo(f"[chimera] no automated unpacker for {packer!r}.")
        from chimera.unpacking import guidance_for
        msg = guidance_for(packer)
        if msg:
            click.echo("[chimera] manual guidance:")
            for line in msg.splitlines():
                click.echo(f"  {line}")
        raise click.exceptions.Exit(2)

    out = Path(out_path) if out_path else src.with_name(
        f"{src.stem}.unpacked{src.suffix}"
    )
    try:
        result = run_unpacker(unpacker, src, out)
    except UnpackError as exc:
        click.echo(f"chimera unpack: {exc}", err=True)
        raise click.exceptions.Exit(3)

    click.echo(f"[chimera] {packer} → unpacked to {result.output}")
    click.echo(f"[chimera] original size: {result.original_size} bytes")
    click.echo(f"[chimera] unpacked size: {result.unpacked_size} bytes")
    if result.notes:
        click.echo(f"[chimera] notes: {result.notes}")
