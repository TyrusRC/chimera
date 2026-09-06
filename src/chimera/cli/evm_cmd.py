"""chimera evm — disassemble EVM smart-contract bytecode and recover its
function selectors, without an Ethereum node. Optionally execute a leaf
`pure`/`view` function against supplied calldata."""

from __future__ import annotations

import json as _json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("evm")
@click.argument("source")
@click.option("--calldata", "calldata",
              help="Hex calldata (selector||abi-args); run the runtime as a "
                   "pure function and print the returned bytes.")
@click.option("--json", "as_json", is_flag=True, help="Emit the tour as JSON.")
def evm(source: str, calldata: str | None, as_json: bool):
    """Triage EVM bytecode given as a hex string or a path to a hex/binary file.

    Splits a constructor (deploy) blob to its runtime, strips solc metadata,
    lists the dispatcher's 4-byte selectors, and prints the disassembly — the
    cheap first look at a contract embedded in a challenge or sample.
    """
    from chimera.parsers.evm import EvmRevert, EvmUnsupported, evm_tour, run_pure, split_deploy_runtime

    p = Path(source)
    try:
        is_file = p.exists()
    except OSError:                       # bytecode hex is longer than a filename
        is_file = False
    if is_file:
        raw = p.read_bytes()
        text = raw.decode("ascii", "ignore").strip()
        code = bytes.fromhex(text[2:] if text.startswith("0x") else text) \
            if all(c in "0123456789abcdefABCDEF" for c in text) and text else raw
    else:
        code = bytes.fromhex(source[2:] if source.startswith("0x") else source)

    tour = evm_tour(code)

    if calldata is not None:
        runtime, _ = split_deploy_runtime(code)
        cd = bytes.fromhex(calldata[2:] if calldata.startswith("0x") else calldata)
        try:
            out = run_pure(runtime, cd)
        except (EvmUnsupported, EvmRevert, ValueError) as exc:
            raise click.ClickException(f"pure-run failed: {exc}")
        click.echo(f"return: 0x{(out or b'').hex()}")
        return

    if as_json:
        click.echo(_json.dumps(tour.to_dict(), indent=2))
        return

    click.echo(f"[chimera] evm {p.name if is_file else source[:32] + '…'}")
    click.echo(f"  size={tour.size}  deploy={tour.is_deploy}  "
               f"runtime_off={tour.runtime_offset:#x}  insns={tour.instruction_count}")
    if tour.metadata_stripped:
        click.echo("  (solc metadata trailer stripped)")
    click.echo(f"  selectors: {[s.selector for s in tour.selectors] or 'none found'}")
    click.echo(tour.disassembly)
