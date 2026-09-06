"""chimera pdftour — statically triage a PDF: recover objects, flag parser traps,
decrypt, and dump inline images. Never renders or executes the document."""

from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("pdftour")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit the full report as JSON.")
@click.option("--password", default="", help="User/owner password to try (default: empty).")
@click.option("--extract-images", "images_dir", type=click.Path(),
              help="Directory to write any inline images to.")
def pdftour(path: str, as_json: bool, password: str, images_dir: str | None):
    """Recon a PDF, flag parser-differential traps, decrypt, list inline images.

    Read-only: the file is never rendered or executed. Recovers objects even
    with no xref/EOF (which strict parsers refuse), surfaces the ambiguities a
    normal library would silently resolve away (duplicate /Root, name-hex-
    obfuscated keys, duplicate/commented objects), and — when the file uses the
    Standard security handler (R2-R6) — derives the key from the empty or given
    password and decrypts the streams to list any hidden inline images.
    """
    from chimera.unpacking.pdf import pdf_tour

    tour = pdf_tour(path, password=password.encode(), extract_images_dir=images_dir)
    report = tour.to_dict()

    if as_json:
        click.echo(_json.dumps(report, indent=2))
        return

    click.echo(f"PDF {report['version']}  objects={report['object_count']}  "
               f"encrypted={report['encrypted']}"
               + (f" key_recovered={report['key_recovered']}" if report['encrypted'] else ""))
    if report["roots"]:
        click.echo("roots:")
        for r in report["roots"]:
            click.echo(f"  {r['key']} -> {r['target']} ({r['type']})")
    if report["traps"]:
        click.echo("traps:")
        for t in report["traps"]:
            click.echo(f"  [{t['kind']}] {t['detail']}")
    if report["images"]:
        click.echo("inline images:")
        for im in report["images"]:
            click.echo(f"  {im['codec']}  {im['size']} bytes  sha256={im['sha256'][:16]}…")
    for note in report["notes"]:
        click.echo(f"note: {note}")
