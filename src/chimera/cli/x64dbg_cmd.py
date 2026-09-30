"""chimera.cli — x64dbg: drive a live x64dbg debugger over its plugin HTTP API."""

from __future__ import annotations

import json

import click

from chimera.cli._root import main


@main.command("x64dbg", context_settings={"ignore_unknown_options": True})
@click.argument("action")
@click.option("-p", "--param", "params", multiple=True, metavar="KEY=VALUE",
              help="Endpoint param (repeatable), e.g. -p addr=0x140001070 -p size=32.")
@click.option("--endpoint", default=None,
              help="For action=raw: the plugin endpoint path (e.g. Memory/Read).")
@click.option("--method", default=None, help="For action=raw: HTTP method (default GET).")
@click.option("--url", default=None,
              help="Plugin base URL (default env CHIMERA_X64DBG_URL or http://127.0.0.1:8888/).")
@click.option("--timeout", default=10.0, type=float, help="Per-call HTTP timeout (s).")
def x64dbg(action, params, endpoint, method, url, timeout):
    """Control a REAL x64dbg on Windows over the x64dbgmcp plugin's HTTP API.

    Full live control — registers, memory, breakpoints, single-step, assemble,
    patch — for a target chimera's in-host oracles can't drive (an
    anti-analysis PE that only reveals itself live on Windows). x64dbg must be
    running there with the MCP plugin loaded; on WSL2 mirrored networking the
    default localhost URL just works.

    \b
      chimera x64dbg is_debugging
      chimera x64dbg exec -p cmd="init C:\\path\\t.exe"
      chimera x64dbg bp_set -p addr=0x140001070
      chimera x64dbg run
      chimera x64dbg regs
      chimera x64dbg mem_read -p addr=rdx -p size=64
      chimera x64dbg raw --endpoint Memory/Read -p addr=0x140001070 -p size=16

    Run `chimera x64dbg actions` to list every action.
    """
    from chimera.dynamic.x64dbg import ACTIONS, x64dbg_call

    if action == "actions":
        click.echo(json.dumps(sorted(ACTIONS) + ["raw"], indent=2))
        return

    kv: dict[str, str] = {}
    for item in params:
        if "=" not in item:
            raise click.UsageError(f"--param must be KEY=VALUE, got {item!r}")
        k, v = item.split("=", 1)
        kv[k] = v

    r = x64dbg_call(action, kv, endpoint=endpoint, method=method, url=url,
                    timeout=timeout)
    click.echo(json.dumps(r, indent=2))
    if not r.get("ok"):
        raise SystemExit(1)
