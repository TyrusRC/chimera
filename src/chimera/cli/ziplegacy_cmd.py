"""chimera.cli — zip-legacy: extract a ZIP using legacy Reduce + ZipCrypto."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("zip-legacy")
@click.argument("path", type=click.Path(exists=True))
@click.option("--password", "-p", default=None, help="ZipCrypto password (if encrypted).")
@click.option("--out-dir", default=None, type=click.Path(), help="Write decoded entries here.")
def zip_legacy_cmd(path, password, out_dir):
    """Extract a ZIP with legacy Reduce compression / ZipCrypto encryption.

    Scans local file headers (robust to a mangled central directory). Example:
    `chimera zip-legacy flareon13.doc -p infected`
    """
    import os

    from chimera.unpacking.zip_legacy import extract_file
    pw = password.encode() if password else None
    for e in extract_file(path, pw):
        d = e.pop("data", None)
        tag = f"{e['name']}  [{e['method']}{' +zipcrypto' if e['encrypted'] else ''}]  usize={e['usize']}"
        if "error" in e:
            click.echo(f"{tag}  ERROR: {e['error']}", err=True)
            continue
        if out_dir and d is not None:
            os.makedirs(out_dir, exist_ok=True)
            dst = os.path.join(out_dir, os.path.basename(e["name"]) or "entry.bin")
            with open(dst, "wb") as fh:
                fh.write(d)
            click.echo(f"{tag} -> {dst}")
        else:
            try:
                click.echo(f"{tag}: {d.decode('utf-8')!r}")
            except (UnicodeDecodeError, AttributeError):
                click.echo(f"{tag}: {len(d or b'')} bytes (binary; use --out-dir)")
