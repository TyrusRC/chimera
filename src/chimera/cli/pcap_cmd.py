"""chimera.cli — pcap: extract HTTP bodies / TCP streams / conversations from a
packet capture via tshark."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("pcap")
@click.argument("path", type=click.Path(exists=True))
@click.option("--action", type=click.Choice(["http", "follow", "conversations"]), default="http")
@click.option("--stream", type=int, default=None, help="tcp.stream index (for --action follow).")
@click.option("--direction", type=click.Choice(["both", "c2s", "s2c"]), default="both")
@click.option("--out-dir", default=None, type=click.Path(), help="Save HTTP bodies here.")
def pcap_cmd(path, action, stream, direction, out_dir):
    """Extract payloads from a capture (HTTP bodies, TCP streams, conversations).

    `chimera pcap capture.pcapng --action http --out-dir ./bodies`
    """
    from chimera.dynamic.pcap_extract import (
        PcapError, conversations, extract_http_bodies, follow_tcp_stream,
        list_http, tshark_available,
    )
    if not tshark_available():
        raise click.ClickException("tshark not found — `apt install tshark`")
    try:
        if action == "http":
            for r in list_http(path):
                if r["method"] or r["code"]:
                    click.echo(f"  stream {r['stream']}: {r['method']} {r['uri']} "
                               f"{('-> ' + r['code']) if r['code'] else ''}")
            bodies = extract_http_bodies(path, out_dir=out_dir)
            click.echo(f"\n{len(bodies)} HTTP bodies:")
            for b in bodies:
                click.echo(f"  stream {b['stream']} {b.get('uri','')}: {b['size']} bytes"
                           f"{(' -> ' + b['file']) if b.get('file') else ''}")
        elif action == "follow":
            if stream is None:
                raise click.ClickException("--stream required for --action follow")
            data = follow_tcp_stream(path, stream, direction)
            click.echo(f"stream {stream} ({direction}): {len(data)} bytes")
            click.echo(data[:2048].hex())
        else:
            click.echo(conversations(path))
    except PcapError as exc:
        raise click.ClickException(str(exc))
