"""chimera gpu — report the host's GPU + cracker acceleration.

Tells you (and an agent) whether this box can offload a hash-crack or
keyspace search to the GPU, and with which tool. See the `gpu-acceleration`
skill for how to turn a `usable` verdict into an actual hashcat/john plan.
"""
from __future__ import annotations

import json

import click

from chimera.cli._root import main


@main.command("gpu")
@click.option("--json", "as_json", is_flag=True, help="Emit the raw report as JSON.")
def gpu_cmd(as_json: bool) -> None:
    """Detect GPU + hashcat/john and report whether GPU cracking is available."""
    from chimera.hw.gpu import detect_gpu

    report = detect_gpu()
    if as_json:
        click.echo(json.dumps(report.as_dict(), indent=2))
        return

    click.echo(report.summary())
    if report.gpus:
        for g in report.gpus:
            bits = [g.name]
            if g.memory_mb:
                bits.append(f"{g.memory_mb} MiB")
            if g.compute_cap:
                bits.append(f"compute {g.compute_cap}")
            if g.driver:
                bits.append(f"driver {g.driver}")
            click.echo("  GPU: " + ", ".join(bits))
    for cracker in (report.hashcat, report.john):
        if cracker.present:
            ver = f" {cracker.version}" if cracker.version else ""
            devs = f" [{', '.join(cracker.gpu_devices)}]" if cracker.gpu_devices else ""
            click.echo(f"  {cracker.name}{ver}: {cracker.path}{devs}")
    if report.note:
        click.echo(f"  note: {report.note}")
