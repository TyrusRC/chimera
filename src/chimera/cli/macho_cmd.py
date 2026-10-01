"""chimera.cli — macho-codesign: read a Mach-O code-sign identifier/CDHash and
list/extract universal (fat) slices."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("macho-codesign")
@click.argument("path", type=click.Path(exists=True))
@click.option("--extract", type=int, default=None, help="Fat-slice index to extract.")
@click.option("--out", default=None, help="Output path for --extract (default <path>.sliceN).")
def macho_codesign_cmd(path, extract, out):
    """Read a Mach-O's CodeDirectory identifier + CDHash, per arch slice.

    The signing identifier can reveal which fat slice is the real program vs a
    decoy (an author's label). With --extract N, writes slice N out as a thin
    Mach-O.
    """
    from chimera.parsers.macho_codesign import (
        MachoCodeSignError, extract_slice, read_code_signatures,
    )
    try:
        for s in read_code_signatures(path):
            click.echo(f"arch@{s.arch_offset:#x}  id={s.identifier!r}  "
                       f"{s.hash_type} cdhash={(s.cdhash or '')[:32]}  signed={s.has_signature}")
        if extract is not None:
            dst = out or f"{path}.slice{extract}"
            n = extract_slice(path, extract, dst)
            click.echo(f"[extract] slice {extract} -> {dst} ({n} bytes)")
    except MachoCodeSignError as exc:
        raise click.ClickException(str(exc))
