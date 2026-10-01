"""chimera.cli — native-oracle: map a binary's segments at their VAs and run a
function from it at native speed, confined (for a brute/oracle loop)."""

from __future__ import annotations

import click

from chimera.cli._root import main


@main.command("native-oracle")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--body", "body", default=None, help="C run inside main() (or use --body-file).")
@click.option("--body-file", type=click.Path(exists=True), default=None,
              help="File with the C body (calls target VAs, prints to stdout).")
@click.option("--preamble-file", type=click.Path(exists=True), default=None,
              help="File with file-scope C (typedefs, tables, helpers).")
@click.option("--cflag", "cflags", multiple=True,
              help="gcc flag (repeatable). Default: -O2. Add -fopenmp for a parallel brute.")
@click.option("--timeout", type=float, default=300)
@click.option("--no-confine", is_flag=True, help="Run UNCONFINED (only for code you trust).")
@click.option("--net", is_flag=True, help="Allow network in the sandbox.")
@click.option("--show-source", is_flag=True, help="Print the generated C harness.")
def native_oracle_cmd(binary, body, body_file, preamble_file, cflags, timeout,
                      no_confine, net, show_source):
    """Run a function from BINARY at native speed as an oracle, confined.

    Maps the binary's segments at their real VAs and runs your C `body` against
    them — the body reaches the target by absolute VA via a WIN64/SYSV typedef,
    e.g. `typedef void (WIN64 *f)(uint32_t,uint32_t,void*); ((f)0x140134ca0)(...)`.
    For a brute/oracle loop too slow to emulate. Needs gcc + bwrap.
    """
    from chimera.dynamic.native_oracle import run_native_oracle
    if body_file:
        body = open(body_file).read()
    if not body:
        raise click.ClickException("provide --body or --body-file")
    preamble = open(preamble_file).read() if preamble_file else ""
    r = run_native_oracle(binary, body, preamble=preamble,
                          cflags=tuple(cflags) if cflags else ("-O2",),
                          timeout=timeout, confine=not no_confine, net=net)
    if show_source and r.get("source"):
        click.echo(r["source"], err=True)
    if not r.get("available"):
        raise click.ClickException(r.get("error") or "unavailable")
    if not r.get("compiled"):
        click.echo("[native-oracle] compile FAILED", err=True)
        click.echo(r.get("stderr", ""), err=True)
        raise click.exceptions.Exit(1)
    if r.get("error"):
        click.echo(f"[native-oracle] {r['error']}", err=True)
    click.echo(f"[native-oracle] {r.get('nsegments')} segments @ base "
               f"{hex(r.get('image_base', 0))}; rc={r.get('returncode')}", err=True)
    if r.get("stderr"):
        click.echo(f"  stderr: {r['stderr'][:400]}", err=True)
    click.echo(r.get("stdout", ""))
