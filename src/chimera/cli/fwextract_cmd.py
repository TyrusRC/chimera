"""chimera.cli — fw-extract: carve UEFI firmware into its modules."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("fw-extract")
@click.argument("firmware", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "extract_dir", type=click.Path(), default=None,
              help="Extract the PE/TE modules to this directory.")
@click.option("--named-only", is_flag=True, help="List only modules with a UI-name.")
def fw_extract(firmware: str, extract_dir: str | None, named_only: bool):
    """Carve a UEFI firmware image (OVMF/BIOS/flash) and list its modules.

    Recurses the firmware volumes and prints one line per FFS module carrying a
    PE32/TE image (GUID, UI-name, size) — the way to spot an implant/bootkit or
    a CTF's malicious DXE. With --out, extracts each as a normal .efi PE to
    analyze further. Needs the 'firmware' extra (uefi_firmware).
    """
    from chimera.unpacking.uefi import carve_firmware, uefi_available
    if not uefi_available():
        raise click.ClickException('uefi_firmware not installed — pip install "chimera[firmware]"')
    r = carve_firmware(firmware, extract_dir=extract_dir)
    if not r.get("available"):
        raise click.ClickException(r["error"])
    if not r.get("is_firmware"):
        raise click.ClickException(r.get("error", "not a UEFI firmware image"))
    if r.get("error"):
        raise click.ClickException(r["error"])
    mods = [m for m in r["modules"] if m["name"]] if named_only else r["modules"]
    click.echo(f"[fw-extract] {r['module_count']} PE/TE modules"
               + (f"; extracted to {r['extract_dir']}" if r["extract_dir"] else ""))
    for m in mods:
        line = f"  {m['kind']:2} {m['size']:>9} B  {m['guid']}  {m['name'] or ''}"
        click.echo(line.rstrip())
