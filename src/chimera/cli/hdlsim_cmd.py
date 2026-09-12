"""chimera.cli — hdl-sim: compile + run a Verilog design (Icarus) as an oracle."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("hdl-sim")
@click.argument("sources", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--top", default=None, help="Top module to elaborate (iverilog -s).")
@click.option("--flag", "flags", multiple=True,
              help="iverilog flag (repeatable). Default: -g2012.")
@click.option("--vvp-flag", "vvp_flags", multiple=True, help="vvp flag (repeatable).")
@click.option("--iverilog", default="iverilog", help="iverilog path (default: PATH).")
@click.option("--vvp", default="vvp", help="vvp path (default: PATH).")
@click.option("--timeout", type=int, default=120)
def hdl_sim_cmd(sources, top, flags, vvp_flags, iverilog, vvp, timeout):
    """Compile a Verilog/SystemVerilog design with Icarus and run it under vvp.

    The HDL analogue of `run-under-wine`: build the sources + testbench and
    print whatever the testbench `$display`s — the way to solve a "reverse this
    core" HDL target. Needs iverilog/vvp (apt install iverilog, or pass explicit
    --iverilog/--vvp paths for a rootless extract).
    """
    from chimera.dynamic.hdl_sim import hdl_sim
    r = hdl_sim(list(sources), top=top,
                extra_flags=tuple(flags) if flags else ("-g2012",),
                vvp_flags=tuple(vvp_flags), iverilog=iverilog, vvp=vvp,
                timeout=timeout)
    if not r.get("available"):
        raise click.ClickException(r["error"])
    if not r.get("compiled"):
        click.echo(f"[hdl-sim] compile FAILED: {r.get('error')}", err=True)
        if r.get("compile_stderr"):
            click.echo(r["compile_stderr"], err=True)
        raise click.exceptions.Exit(1)
    click.echo(f"[hdl-sim] compiled OK; vvp rc={r.get('returncode')}")
    if r.get("stderr"):
        click.echo(f"  stderr: {r['stderr'][:400]}", err=True)
    click.echo(r.get("stdout", ""))
