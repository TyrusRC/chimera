"""chimera.cli — crypto-triage: detect keystream reuse across ciphertexts and
crib-drag to recover plaintext (multi-time-pad attack), no key needed."""

from __future__ import annotations

import json

import click

from chimera.cli._root import main


@main.command("crypto-triage")
@click.argument("inputs", nargs=-1, required=True)
@click.option("--enc", type=click.Choice(["hex", "base64", "file", "raw"]), default="file",
              help="How each INPUT is given (default: file paths).")
@click.option("--crib", default=None, help="Known/guessed plaintext fragment to drag.")
def crypto_triage_cmd(inputs, enc, crib):
    """Detect shared-keystream (multi-time-pad) reuse across ≥2 ciphertexts.

    Scores the reuse signal and, with --crib, recovers the other plaintexts
    where the crib matches. Example:
    `chimera crypto-triage post_1.bin post_2.bin --crib 'the treasure'`
    """
    from chimera.crypto_triage import run as triage_run
    if len(inputs) < 2:
        raise click.ClickException("need at least 2 ciphertexts")
    res = triage_run(list(inputs), enc=enc, crib=crib)
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"verdict: {res['verdict']}  ({res['reuse_pairs']}/{len(res['pairs'])} pairs)")
    for p in res["pairs"]:
        click.echo(f"  [{p['i']}^{p['j']}] prefix={p['identical_prefix']} "
                   f"zero_run={p['longest_zero_run']} printable_xor={p['printable_xor_frac']} "
                   f"reuse={p['reuse_signal']}")
    if crib and res.get("crib_hits"):
        click.echo(f"\ncrib '{crib}' hits (recovered plaintext):")
        click.echo(json.dumps(res["crib_hits"][:20], indent=2))
