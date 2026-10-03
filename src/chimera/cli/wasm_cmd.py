"""chimera wasm-decompile / wasm-oracle — WebAssembly analysis commands."""

from __future__ import annotations

import json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("wasm-decompile")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", "out_dir", type=click.Path(), default=None,
              help="Output directory (default: <name>_wasm beside the input).")
@click.option("--wat", is_flag=True, help="Also emit the full .wat text disassembly.")
def wasm_decompile(path: str, out_dir: str | None, wat: bool):
    """Decompile a .wasm module to a C-like form (works on stripped/Go builds).

    Ships the recipe that survives a stripped Go module: a binaryen round-trip
    (`wasm-opt -all`) then wabt's `wasm-decompile` (which crashes on the raw
    file). Output is large and written to disk; read/grep the file. Needs wabt +
    binaryen (apt install wabt binaryen, or set $CHIMERA_WASM_TOOLS).
    """
    from chimera.adapters import wabt as wabt_mod
    from chimera.adapters.wabt import WasmToolError

    out = out_dir or f"{Path(path).with_suffix('')}_wasm"
    try:
        result = wabt_mod.decompile(Path(path), Path(out))
        if wat:
            wat_path = Path(out) / "module.wat"
            wabt_mod.wat_disassemble(Path(path), wat_path)
            result["wat"] = str(wat_path)
    except WasmToolError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"[chimera] decompiled {Path(path).name} → {result['line_count']} lines")
    click.echo(f"  {result['decompiled']}")
    if result.get("wat"):
        click.echo(f"  wat: {result['wat']}")
    click.echo(f"  next: grep the flag/crypto path, or run: chimera wasm-oracle {path} ...")


@main.command("wasm-oracle")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.argument("inputs", nargs=-1)
@click.option("-e", "--export", "export", default="check",
              help="js.Global().Set-exported function to call (default: check).")
@click.option("--trace", is_flag=True,
              help="Instrument (--log-execution) and report the executed function subtree.")
@click.option("--wasm-exec", type=click.Path(exists=True), default=None,
              help="Path to wasm_exec.js (default: sibling of the module).")
def wasm_oracle(path: str, inputs: tuple[str, ...], export: str, trace: bool,
                wasm_exec: str | None):
    """Run a Go-WASM module headless under Node and call export(input).

    Reaches the real entry point of a Go-WASM target (published at runtime via
    `js.Global().Set`, so not a wasm export): loads wasm_exec.js, `go.run`s the
    module without awaiting, then calls `export` with each INPUT and prints the
    return. With --trace, returns the function subtree each input executed
    (highest index first — the Go main package is last). Needs node (+ wabt/
    binaryen for --trace).
    """
    from chimera.dynamic import wasm_oracle as wo

    if not inputs:
        raise click.ClickException("provide at least one input string")
    wx = Path(wasm_exec) if wasm_exec else None
    try:
        if trace:
            result = wo.trace(Path(path), list(inputs), export=export, wasm_exec=wx)
        else:
            result = wo.run_oracle(Path(path), list(inputs), export=export, wasm_exec=wx)
    except wo.WasmOracleError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"[chimera] {'Go-' if result['go'] else ''}WASM oracle: {export}()")
    for rec in result["results"]:
        inp = rec["input"]
        label = f"<{len(inp)} chars>" if len(inp) > 48 else json.dumps(inp)
        if rec.get("error"):
            click.echo(f"  {label} => ERROR {rec['error']}")
        else:
            click.echo(f"  {label} => {json.dumps(rec['result'])}")
        if trace:
            click.echo(f"      events={rec['total_events']} funcs={len(rec['func_indices'])} "
                       f"top={rec['top_funcs']}")
