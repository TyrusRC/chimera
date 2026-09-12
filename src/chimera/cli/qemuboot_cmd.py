"""chimera.cli — qemu-boot: run a firmware/disk image under QEMU as an oracle."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("qemu-boot")
@click.option("--bios", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Firmware image (e.g. an OVMF bios.bin).")
@click.option("--disk", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Raw disk image (mounted copy-on-write).")
@click.option("--input", "input_lines", multiple=True,
              help="Console line to type into the guest after boot (repeatable).")
@click.option("--boot-wait", type=float, default=8.0, help="Seconds before first input.")
@click.option("--line-delay", type=float, default=1.5, help="Seconds between input lines.")
@click.option("--timeout", type=int, default=90, help="Hard timeout (s).")
@click.option("--net", is_flag=True, help="Allow guest networking (default: off).")
def qemu_boot_cmd(bios, disk, input_lines, boot_wait, line_delay, timeout, net):
    """Boot a firmware/disk image under QEMU headless and capture its console.

    The firmware analogue of run-under-wine: reveals runtime behaviour a static
    carve can't — a boot-stage ransom note, a flag a bootkit prints. Drive an
    EFI/DOS shell with repeated --input lines. Confined: no network by default,
    disk copy-on-write, hard timeout. Needs qemu-system-x86_64.

    \b
      chimera qemu-boot --bios bios.bin --disk disk.img
      chimera qemu-boot --bios bios.bin --disk disk.img \\
          --input 'fs0:' --input 'ls' --input 'decrypt_file f.c4tb PASSWORD'
    """
    from chimera.dynamic.qemu_boot import qemu_boot, qemu_available
    if not qemu_available():
        raise click.ClickException("qemu-system-x86_64 not found — apt install qemu-system-x86")
    r = qemu_boot(bios=bios, disk=disk, input_lines=tuple(input_lines),
                  boot_wait=boot_wait, line_delay=line_delay, timeout=timeout, net=net)
    if not r.get("available"):
        raise click.ClickException(r["error"])
    if r.get("error"):
        raise click.ClickException(r["error"])
    click.echo(f"[qemu-boot] {r['bytes']} bytes captured; inputs_sent={r['inputs_sent']}"
               f"{'; TIMED OUT' if r['timed_out'] else ''}")
    click.echo(r["output"])
