"""chimera.cli — vmp cmd commands.

`chimera vmp-devirt` shells out to Mergen (NaC-L/Mergen, MIT) to
devirtualise a VMProtect / Themida-protected function. The analyst
supplies the binary plus the start address of the VM entry; Mergen
lifts the handler chain to LLVM IR and emits a cleaned artefact that
can be re-decompiled through Ghidra or r2.
"""

from __future__ import annotations

import asyncio
import logging

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# vmp-devirt — Mergen VMProtect / Themida devirtualization
# ----------------------------------------------------------------------


@main.command("vmp-devirt")
@click.argument("path", type=click.Path(exists=True))
@click.option("--start", "start", required=True, type=str,
              help="Start address of the virtualised function (e.g. 0x140001000).")
@click.option("-o", "--out", "out_dir", type=click.Path(), required=True,
              help="Output directory for Mergen artefacts (LLVM IR / cleaned binary).")
@click.option("--timeout", type=int, default=600,
              help="Subprocess timeout in seconds (default: 600).")
@click.option("--mergen-bin", type=click.Path(exists=True), default=None,
              help="Path to the mergen binary (default: $PATH / $CHIMERA_MERGEN_BIN).")
def vmp_devirt(path: str, start: str, out_dir: str, timeout: int,
               mergen_bin: str | None):
    """Devirtualise a VMProtect / Themida-protected routine via Mergen.

    PATH is the protected binary (PE for VMP, PE or ELF for Themida).
    --start is the address of the VM entry — get it from your prior
    Ghidra / r2 pass, the location where control jumps into the
    obfuscated dispatcher. Mergen lifts the handler chain to LLVM IR
    and writes the cleaned artefact under -o for re-decompilation.

    Requires the `mergen` binary on PATH or via --mergen-bin.
    Install from https://github.com/NaC-L/Mergen (MIT).
    """
    from chimera.adapters.mergen_adapter import MergenAdapter

    adapter = MergenAdapter(binary=mergen_bin)
    if not adapter.is_available():
        raise click.ClickException(
            "mergen binary not found. Install from "
            "https://github.com/NaC-L/Mergen, put it on PATH, "
            "or pass --mergen-bin / set CHIMERA_MERGEN_BIN."
        )

    click.echo(f"[chimera] mergen: devirtualising {path} @ {start} -> {out_dir}")
    options = {"start": start, "out_dir": out_dir, "timeout": timeout}
    result = asyncio.run(adapter.analyze(path, options))

    if result.get("error"):
        click.echo(f"[chimera] mergen FAILED: {result['error']}", err=True)
        raise click.exceptions.Exit(3)

    lifted = result.get("lifted_functions") or []
    devirt = result.get("devirt_output")
    click.echo(
        f"[chimera] mergen: {len(lifted)} lifted artefact(s) written to "
        f"{result.get('output_dir')}"
    )
    if devirt:
        click.echo(f"[chimera] mergen: primary output -> {devirt}")
