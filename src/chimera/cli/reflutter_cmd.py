"""chimera flutter-patch — reFlutter dynamic instrumentation / traffic MITM.

Complements `flutter-extract` (static B(l)utter). Flutter apps ignore the system
proxy and bundle their own CA, so normal MITM fails; reFlutter repackages the
APK with a patched engine that routes traffic through your proxy (pinning off),
or dumps Dart code offsets at runtime. Requires the `reflutter` tool
(`pip install reflutter`); needs network to fetch the matching patched engine.
"""
from __future__ import annotations

import logging

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


@main.command("flutter-patch")
@click.argument("apk", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", type=click.Path(), required=True,
              help="Output directory for the patched release.RE.apk.")
@click.option("--mode", type=click.Choice(["traffic", "offset"]), default="traffic",
              help="traffic: route HTTP(S) through a proxy + disable pinning; "
                   "offset: dump Dart code offsets at runtime.")
@click.option("--proxy", "proxy_ip", default=None, metavar="IP",
              help="Proxy (Burp/mitmproxy) IP the app should dial (traffic mode).")
@click.option("--reflutter-bin", type=click.Path(exists=True), default=None,
              help="Path to the reflutter binary (default: $PATH / $CHIMERA_REFLUTTER_BIN).")
def flutter_patch(apk: str, out_dir: str, mode: str, proxy_ip: str | None,
                  reflutter_bin: str | None):
    """Repackage a Flutter APK for traffic interception or offset dumping."""
    from chimera.adapters.reflutter_adapter import ReflutterAdapter

    adapter = ReflutterAdapter(binary_path=reflutter_bin)
    if not adapter.is_available():
        raise click.ClickException(
            "reflutter not found. Install with `pip install reflutter`, put it "
            "on PATH, or pass --reflutter-bin / set CHIMERA_REFLUTTER_BIN.")
    if mode == "traffic" and not proxy_ip:
        raise click.ClickException("traffic mode needs --proxy IP")

    res = adapter.patch(apk, out_dir, mode=mode, proxy_ip=proxy_ip)
    click.echo(f"[chimera] flutter-patch ({res.mode}): "
               f"{'ok' if res.success else 'FAILED'}")
    if res.patched_apk:
        click.echo(f"  patched APK: {res.patched_apk}")
    if res.hint:
        click.echo(f"  {res.hint}")
    if not res.success:
        if res.stderr:
            click.echo(f"  stderr: {res.stderr.strip()[:500]}")
        raise click.ClickException("reflutter did not produce a patched APK "
                                   "(needs network for the matching engine; check stderr).")
