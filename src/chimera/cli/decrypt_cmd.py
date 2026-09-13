"""chimera decrypt — RC4 / XOR / ChaCha20 / Salsa20 a blob with a known key.

The reusable last step of a network-capture or file-encryptor challenge once the
key is recovered. Backed by chimera.symcrypt.
"""
from __future__ import annotations

import json as _json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("decrypt")
@click.argument("data", required=False)
@click.option("--in-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Read ciphertext from a file instead of the DATA argument.")
@click.option("--key", "key", required=True, help="Decryption key (see --key-enc).")
@click.option("--algo", type=click.Choice(["rc4", "xor", "chacha20", "salsa20"]),
              default="rc4", show_default=True)
@click.option("--in-enc", "in_encoding", type=click.Choice(["raw", "hex", "base64"]),
              default="raw", show_default=True, help="How DATA is encoded.")
@click.option("--key-enc", "key_encoding", type=click.Choice(["raw", "hex", "utf16le"]),
              default="raw", show_default=True,
              help="How --key is encoded (utf16le = a hex-digest string as UTF-16LE).")
@click.option("--nonce", default=None,
              help="Nonce for chacha20 (8/12 B) / salsa20 (8 B); decoded with --nonce-enc.")
@click.option("--nonce-enc", "nonce_encoding", type=click.Choice(["raw", "hex", "base64"]),
              default="hex", show_default=True, help="How --nonce is encoded.")
@click.option("--counter", type=int, default=0, show_default=True,
              help="Initial block counter for chacha20 (the in[12] state word).")
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON.")
def decrypt(data: str | None, in_file: str | None, key: str, algo: str,
            in_encoding: str, key_encoding: str, nonce: str | None,
            nonce_encoding: str, counter: int, as_json: bool):
    """Decrypt DATA (or --in-file) with --key using RC4 / XOR / ChaCha20 / Salsa20."""
    from chimera.symcrypt import run
    if in_file:
        blob: str | bytes = Path(in_file).read_bytes()
    elif data is not None:
        blob = data
    else:
        raise click.UsageError("provide DATA or --in-file.")
    r = run(blob, key, algo=algo, in_encoding=in_encoding, key_encoding=key_encoding,
            nonce=nonce or b"", nonce_encoding=nonce_encoding, counter=counter)
    if as_json:
        click.echo(_json.dumps(r, indent=2))
        return
    if r.get("error"):
        raise click.ClickException(r["error"])
    click.echo(f"[decrypt] {algo} -> {r['byte_count']} bytes")
    click.echo(f"  hex:       {r['hex']}")
    click.echo(f"  printable: {r['printable']}")
    if "text_utf8" in r:
        click.echo(f"  utf-8:     {r['text_utf8']!r}")
    if "text_utf16le" in r:
        click.echo(f"  utf-16le:  {r['text_utf16le']!r}")
