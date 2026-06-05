"""chimera.cli — hermes-decomp (React Native) commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


@main.command("hermes-decompile")
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: alongside input).")
@click.option("--bin", "binary", type=click.Path(exists=True), default=None,
              help="Path to hermes-decomp binary.")
@click.option("--timeout", type=int, default=300)
def hermes_decompile(path: str, out_dir: str | None, binary: str | None,
                     timeout: int):
    """Decompile a React Native Hermes bytecode bundle.

    Uses SymbioticSec/hermes-decomp (HBC v40-99, control-flow recovery,
    closure resolution). PATH can be either a raw .hbc file or an APK's
    index.android.bundle / IPA's main.jsbundle.
    """
    from chimera.adapters.hermes_decomp import HermesDecompAdapter, detect_hbc
    adapter = HermesDecompAdapter(binary=binary)
    if not adapter.is_available():
        raise click.ClickException(
            "hermes-decomp not found. Install from "
            "https://github.com/SymbioticSec/hermes-decomp, put it on PATH, "
            "or pass --bin / set CHIMERA_HERMES_DECOMP_BIN."
        )
    target = Path(path)
    if target.is_dir():
        detected = detect_hbc(target)
        if detected is None:
            raise click.ClickException(
                f"no Hermes bundle found under {path!r}; "
                "expected index.android.bundle / main.jsbundle / *.hbc"
            )
        target = detected
        click.echo(f"[chimera] hermes-decomp: detected bundle {target}")
    res = asyncio.run(adapter.analyze(str(target), {
        "output_dir": out_dir, "timeout": timeout,
    }))
    if not res.get("decompiled"):
        click.echo(f"[chimera] hermes-decomp FAILED: {res.get('error') or 'unknown'}",
                   err=True)
        raise click.exceptions.Exit(3)
    click.echo(f"[chimera] hermes-decomp: wrote {res['size']} bytes to "
               f"{res['output_file']}")


@main.command("rust-decompile")
@click.argument("path", type=click.Path(exists=True))
@click.option("--limit", type=int, default=20,
              help="Max functions to decompile.")
@click.option("--addresses", multiple=True,
              help="Specific 0x... addresses to decompile (repeatable).")
@click.option("--force/--no-force", default=False,
              help="Try Oxidizer even if the binary doesn't look like Rust.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]),
              default="text")
def rust_decompile(path: str, limit: int, addresses: tuple,
                   force: bool, fmt: str):
    """Decompile a Rust binary via Oxidizer (angr).

    Falls back with a clear message if angr isn't installed. Detects
    Rust by panic-handler string signature; pass --force to skip the
    check on stripped binaries.
    """
    from chimera.adapters.oxidizer_adapter import OxidizerAdapter
    adapter = OxidizerAdapter()
    if not adapter.is_available():
        raise click.ClickException(
            "angr not installed; `pip install angr` to enable Oxidizer."
        )
    res = asyncio.run(adapter.analyze(path, {
        "limit": limit,
        "addresses": list(addresses) or None,
        "force": force,
    }))
    if not res.get("available", True):
        raise click.ClickException(res.get("error") or "oxidizer unavailable")
    if not res.get("is_rust", True) and not force:
        click.echo(res.get("error") or "binary does not look like Rust",
                   err=True)
        raise click.exceptions.Exit(2)
    if fmt == "json":
        click.echo(json.dumps(res, indent=2))
        return
    for fn in res.get("functions") or []:
        click.echo(f"// {fn['address']}  {fn['name']}")
        if fn.get("code"):
            click.echo(fn["code"])
        else:
            click.echo(f"// (no output: {fn.get('error') or 'empty'})")
        click.echo()
