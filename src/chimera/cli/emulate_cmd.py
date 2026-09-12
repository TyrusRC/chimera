"""chimera emulate — run one function in isolation to deobfuscate its output."""

from __future__ import annotations

import click

from chimera.cli._root import main


def _parse_int(ctx, param, value):
    """Accept 0x-hex or decimal for repeatable integer options."""
    out = []
    for v in value:
        try:
            out.append(int(v, 0))
        except ValueError:
            raise click.BadParameter(f"not an integer: {v!r}")
    return tuple(out)


@main.command("emulate")
@click.argument("path", type=click.Path(exists=True))
@click.option("--addr", "address", required=True, help="Function address (0x…).")
@click.option("--arch", type=click.Choice(["x86_64", "arm64"]), default=None,
              help="Target arch; auto-detected from the binary when omitted.")
@click.option("--arg", "args", multiple=True, callback=_parse_int,
              help="Integer argument (repeatable), in register order.")
@click.option("--read-back", "read_back", multiple=True,
              help="Memory to dump after the run as ADDR:LEN (repeatable).")
@click.option("--max-insns", type=int, default=200_000)
@click.option("--full-image", is_flag=True,
              help="Map the WHOLE PE (x86-64), stub calls that leave the code "
                   "sections, lazily map faults, and capture printable writes — "
                   "for obfuscated computed-goto/MBA VMs. Needs pefile.")
def emulate(path: str, address: str, arch: str | None, args, read_back, max_insns: int,
            full_image: bool):
    """Emulate the function at --addr and print its return value + any output buffers.

    Default maps only the function's own bytes — a call into an import or a
    syscall stops the run (self-contained hash/decrypt/checksum routines).
    --full-image maps the entire PE and stubs external calls, so an obfuscated
    VM whose dispatch reads a data blob runs to completion.
    """
    from chimera.dynamic.emulate import (emulate_function, emulate_pe_function,
                                         unicorn_available)

    if not unicorn_available():
        raise click.ClickException(
            'unicorn not installed — pip install "chimera[emulate]"')

    if full_image:
        rb = []
        for spec in read_back:
            addr_s, _, len_s = spec.partition(":")
            rb.append((int(addr_s, 0), int(len_s or "16", 0)))
        result = emulate_pe_function(path, address, args=tuple(args),
                                     read_back=tuple(rb),
                                     max_insns=max(max_insns, 2_000_000))
        if not result["available"]:
            raise click.ClickException(result["error"])
        click.echo(f"[chimera] emulate {address} (full-image)  "
                   f"insns={result['instructions']} edges={result['edges']} "
                   f"returned={result['returned']}")
        if result["error"]:
            click.echo(f"  note: {result['error']}")
        if result["extern_calls"]:
            click.echo(f"  stubbed externs: {', '.join(result['extern_calls'][:12])}")
        for w in result["ascii_writes"]:
            click.echo(f"  wrote {w['address']}: {w['text']!r}")
        for r in result["read_back"]:
            click.echo(f"  {r['address']}: {r.get('hex', r.get('error'))}")
        return

    if arch is None:
        from chimera.model.binary import BinaryInfo
        a = BinaryInfo.from_path(path).arch.value
        arch = "arm64" if a.startswith("arm64") else a
        if arch not in ("x86_64", "arm64"):
            raise click.ClickException(
                f"could not emulate arch {a!r}; pass --arch x86_64|arm64")

    rb = []
    for spec in read_back:
        addr_s, _, len_s = spec.partition(":")
        rb.append((int(addr_s, 0), int(len_s or "16", 0)))

    result = emulate_function(path, address, arch=arch, args=tuple(args),
                              read_back=tuple(rb), max_insns=max_insns)
    if not result["available"]:
        raise click.ClickException(result["error"])
    click.echo(f"[chimera] emulate {address} ({arch})  "
               f"insns={result['instructions']} returned={result['returned']}")
    if result["error"]:
        click.echo(f"  note: {result['error']}")
    click.echo(f"  return = {result['return_value']}  ({result['return_hex']})")
    for r in result["read_back"]:
        if "error" in r:
            click.echo(f"  {r['address']}: <{r['error']}>")
        else:
            click.echo(f"  {r['address']}: {r['hex']}  |{r['ascii']}|")
