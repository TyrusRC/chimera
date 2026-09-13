"""chimera rsa-solve — recover an RSA plaintext from N/e/c (+ optional d/p/q)."""

from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("rsa-solve")
@click.option("-n", "--modulus", "n", required=True, help="Modulus N.")
@click.option("-c", "--ciphertext", "c", required=True, help="Ciphertext c.")
@click.option("-e", "--exponent", "e", default="10001", show_default=True,
              help="Public exponent e (default 0x10001).")
@click.option("-d", "--private", "d", default=None, help="Private exponent d, if known.")
@click.option("-p", "p", default=None, help="Prime p, if known.")
@click.option("-q", "q", default=None, help="Prime q, if known.")
@click.option("--base", type=click.Choice(["hex", "dec", "b64"]), default="hex",
              show_default=True, help="How bare (no-0x) numeric inputs are read.")
@click.option("--factor", is_flag=True, help="Try Fermat factorization of N (close primes).")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def rsa_solve(n: str, c: str, e: str, d: str | None, p: str | None, q: str | None,
              base: str, factor: bool, as_json: bool):
    """Recover an RSA plaintext.

    With only N/e/c it computes m = c^e mod N — which returns the plaintext when
    the encryptor "encrypted" with the private exponent (a classic bug), or
    verifies a signature. With d, or p and q, it decrypts properly.
    """
    from chimera.rsatool import RsaError, parse_int, rsa_recover

    try:
        r = rsa_recover(
            n=parse_int(n, base=base), c=parse_int(c, base=base),
            e=parse_int(e, base=base), d=parse_int(d, base=base),
            p=parse_int(p, base=base), q=parse_int(q, base=base),
            factor=factor)
    except RsaError as exc:
        raise click.ClickException(str(exc))

    out = r.to_dict()
    if as_json:
        click.echo(_json.dumps(out, indent=2))
        return
    click.echo(f"[rsa-solve] {out['operation']}")
    for s in out["signals"]:
        click.echo(f"  {s}")
    click.echo(f"  m (hex):        {out['m_hex']}")
    click.echo(f"  bytes (big):    {out['bytes_big_hex']}")
    click.echo(f"  bytes (little): {out['bytes_little_hex']}")
    if "text_big" in out:
        click.echo(f"  text (big):     {out['text_big']!r}")
    if "text_little" in out:
        click.echo(f"  text (little):  {out['text_little']!r}")
    click.echo(f"  printable (big):    {out['printable_big']}")
    click.echo(f"  printable (little): {out['printable_little']}")
