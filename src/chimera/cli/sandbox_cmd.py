"""chimera sandbox-run — run a program confined by bubblewrap: isolated
namespaces, network off by default, throwaway /tmp and $HOME. For untrusted
targets (crackmes, malware, CTF binaries). Backed by chimera.dynamic.sandbox."""

from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("sandbox-run")
@click.argument("argv", nargs=-1, required=True)
@click.option("--net", is_flag=True, help="Allow network (default: OFF).")
@click.option("--wine", is_flag=True, help="Run the target under Wine.")
@click.option("--ro", "ro_binds", multiple=True, help="Extra read-only bind (src or src:dst).")
@click.option("--rw", "rw_binds", multiple=True, help="Writable bind (src or src:dst).")
@click.option("--workdir", default=None, help="Working directory inside the sandbox.")
@click.option("--timeout", type=float, default=30, help="Kill after N seconds.")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as JSON.")
def sandbox_run(argv, net, wine, ro_binds, rw_binds, workdir, timeout, as_json):
    """Run ARGV... in a bubblewrap sandbox (network off unless --net)."""
    from chimera.dynamic.sandbox import run_sandboxed

    res = run_sandboxed(list(argv), ro_binds=tuple(ro_binds), rw_binds=tuple(rw_binds),
                        workdir=workdir, net=net, wine=wine, timeout=timeout)
    if as_json:
        click.echo(_json.dumps(res, indent=2))
        return
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"[chimera] sandbox exit={res['returncode']} "
               f"timed_out={res['timed_out']} net={'on' if net else 'off'}")
    if res["stdout"]:
        click.echo("--- stdout ---"); click.echo(res["stdout"])
    if res["stderr"].strip():
        click.echo("--- stderr ---"); click.echo(res["stderr"])
