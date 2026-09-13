"""chimera.cli — patch cmd commands."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# patch — in-place PE/ELF/Mach-O byte editor with a recipe library
# ----------------------------------------------------------------------


@main.command("patch")
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--addr", type=str, default=None,
              help="Virtual address to patch (hex). Pair with --bytes.")
@click.option("--bytes", "raw_bytes", type=str, default=None,
              help="Bytes to write as a hex string. Pair with --addr.")
@click.option("--asm", "asm_src", type=str, default=None,
              help="Assemble source at --addr and write it (keystone), e.g. "
                   "--asm 'xor eax,eax; ret'. Relative branches encode against "
                   "--addr. Pair with --addr; alternative to --bytes.")
@click.option("--asm-arch", "asm_arch", type=str, default=None,
              help="Arch for --asm (x86_64/x86/arm64/arm/thumb). "
                   "Default: auto-detected from the binary.")
@click.option("--nop", "nop_addrs", type=str, multiple=True, metavar="ADDR",
              help="NOP the instruction at ADDR (hex), auto-sized by disassembly "
                   "so short and near jumps both work — repeatable. The 'just NOP "
                   "the check' patch. Use --nop-count for multi-instruction spans.")
@click.option("--nop-count", "nop_count", type=int, default=1, show_default=True,
              help="Instructions to NOP at each --nop address.")
@click.option("--json", "json_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Apply a batch of patches from a JSON file. Schema: "
                   "{patches:[{address, bytes_hex, description?}]}.")
@click.option("--recipe", "recipes", multiple=True,
              help="Apply a bundled recipe by name (repeatable).")
@click.option("--list-recipes", is_flag=True,
              help="List bundled recipes and exit.")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output path (default: <binary>.patched.<ext>)")
@click.option("--dry-run", is_flag=True,
              help="Print the diff summary and do NOT write the output file.")
def patch(binary: str, addr: str | None, raw_bytes: str | None,
          asm_src: str | None, asm_arch: str | None,
          nop_addrs: tuple[str, ...], nop_count: int,
          json_path: str | None, recipes: tuple[str, ...],
          list_recipes: bool, out_path: str | None, dry_run: bool):
    """Apply byte-level patches to a PE / ELF / Mach-O binary.

    \b
    Examples:
      chimera patch app.exe --addr 0x14001234 --bytes 909090
      chimera patch app.exe --addr 0x14001234 --asm 'xor eax,eax; ret'
      chimera patch game.exe --nop 0x401486 --nop 0x40149d --dry-run
      chimera patch sample.elf --recipe elf-ptrace-zero
      chimera patch sample.exe --recipe pe-isdebuggerpresent-nop --dry-run
      chimera patch app.exe --json patches.json --out app.cracked.exe
    """
    import json as _json
    from chimera.patching import AssembleError, BinaryPatcher, PatchError, PatchPlan
    from chimera.patching.disasm import DisasmError
    from chimera.patching.recipes import (
        apply_recipe,
        load_bundled_recipes,
    )

    if list_recipes:
        for name, r in sorted(load_bundled_recipes().items()):
            click.echo(f"  {name:<40s} [{','.join(r.applies_to)}]  {r.description}")
        return

    if not (addr or nop_addrs or json_path or recipes):
        raise click.UsageError(
            "Provide --addr (+--bytes/--asm), --nop, --json, --recipe, or --list-recipes."
        )
    if raw_bytes and asm_src:
        raise click.UsageError("Use --bytes or --asm, not both.")
    if (raw_bytes or asm_src) and not addr:
        raise click.UsageError("--bytes/--asm need --addr.")

    try:
        patcher = BinaryPatcher.open(binary)
    except PatchError as exc:
        click.echo(f"chimera patch: {exc}", err=True)
        raise click.exceptions.Exit(1)

    try:
        if addr and raw_bytes:
            patcher.patch(int(addr, 16), bytes.fromhex(raw_bytes),
                          description="--addr/--bytes")
        if addr and asm_src:
            patcher.patch_asm(int(addr, 16), asm_src, arch=asm_arch,
                              description=f"--asm {asm_src!r}")
        for na in nop_addrs:
            patcher.nop(int(na, 16), count=nop_count, description="--nop")
        if json_path:
            blob = _json.loads(Path(json_path).read_text())
            for step in blob.get("patches", []):
                plan = PatchPlan(
                    bytes_=bytes.fromhex(step["bytes_hex"]),
                    virtual_address=int(step["address"], 16),
                    description=step.get("description", "batch"),
                )
                patcher.apply(plan)
        if recipes:
            db = load_bundled_recipes()
            for name in recipes:
                if name not in db:
                    raise click.UsageError(f"unknown recipe {name!r}")
                apply_recipe(patcher, db[name])
    except (PatchError, AssembleError, DisasmError) as exc:
        click.echo(f"chimera patch: {exc}", err=True)
        raise click.exceptions.Exit(2)

    click.echo(f"Patches applied: {len(patcher.results)}")
    for r in patcher.results:
        va = f"@VA {r.virtual_address:#x}" if r.virtual_address is not None else "@OFF"
        click.echo(f"  {va:>18s}  off={r.file_offset:#x}  {r.before.hex():<16s} -> {r.after.hex():<16s}  {r.description}")

    if not patcher.results:
        click.echo("(no patches to write)")
        return

    out = patcher.save(out_path, dry_run=dry_run)
    if dry_run:
        click.echo(f"Dry-run: would write {out}")
    else:
        click.echo(f"Wrote {out}")
