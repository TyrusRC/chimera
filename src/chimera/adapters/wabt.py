"""wabt + binaryen command wrappers for WebAssembly analysis.

These two toolchains do the heavy lifting the pure-Python parser can't:

* **wasm2wat** (wabt) — textual disassembly.
* **wasm-decompile** (wabt) — C-like decompilation. It ``assert``-crashes on a
  stripped module straight off disk, but works after a **binaryen round-trip**
  (``wasm-opt`` reads and re-serialises the module), so the decompile path ships
  as that two-step recipe rather than the single tool.
* **wasm-opt** (binaryen) — the round-trip, and ``--log-execution`` instrumentation
  for the dynamic tracer. Go 1.24+ wasm uses post-MVP features, so every
  invocation passes ``-all`` or wasm-opt rejects the module.

Tool discovery: ``$CHIMERA_WASM_TOOLS`` (os.pathsep-joined dirs) first, then
``$PATH``. binaryen ships ``libbinaryen.so`` beside its binaries, so the run
environment prepends the sibling ``lib`` dirs to ``LD_LIBRARY_PATH``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_TIMEOUT = 300


def _find_tool(name: str) -> str | None:
    override = os.environ.get("CHIMERA_WASM_TOOLS")
    if override:
        for d in override.split(os.pathsep):
            cand = Path(d) / name
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    return shutil.which(name)


def _run_env(tool_path: str) -> dict:
    """Environment for running a tool, with binaryen's sibling lib dir added to
    LD_LIBRARY_PATH (its binaries dynamically link libbinaryen.so)."""
    env = dict(os.environ)
    base = Path(tool_path).resolve().parent
    libs = [base.parent / "lib" / "x86_64-linux-gnu", base.parent / "lib", base]
    extra = os.pathsep.join(str(p) for p in libs if p.is_dir())
    if extra:
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{extra}{os.pathsep}{prev}" if prev else extra
    return env


def tools_available() -> dict[str, str | None]:
    return {t: _find_tool(t) for t in ("wasm2wat", "wasm-opt", "wasm-decompile")}


class WasmToolError(RuntimeError):
    pass


def _exec(tool: str, args: list[str], *, capture: bool = False) -> str:
    path = _find_tool(tool)
    if not path:
        raise WasmToolError(
            f"{tool} not found — install wabt/binaryen (apt install wabt binaryen) "
            f"or set $CHIMERA_WASM_TOOLS to the dir holding them")
    try:
        proc = subprocess.run(
            [path, *args], env=_run_env(path), timeout=_TIMEOUT,
            capture_output=True, text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise WasmToolError(f"{tool} timed out after {_TIMEOUT}s") from exc
    if proc.returncode != 0:
        raise WasmToolError(f"{tool} failed (rc={proc.returncode}): "
                            f"{(proc.stderr or proc.stdout).strip()[:400]}")
    return proc.stdout if capture else ""


def wat_disassemble(wasm_path: Path, out_path: Path) -> Path:
    """wasm2wat the module to `out_path`. `--enable-all` for post-MVP features."""
    _exec("wasm2wat", ["--enable-all", str(wasm_path), "-o", str(out_path)])
    return out_path


def decompile(wasm_path: Path, out_dir: Path) -> dict:
    """The working stripped-Go recipe: binaryen round-trip, then wasm-decompile.

    `wasm-opt -all <in> -o clean.wasm` re-serialises the module (no passes), which
    is what unbreaks wasm-decompile's name assertion. Returns the output paths,
    the decompilation's line count, and a head preview.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    clean = out_dir / "clean.wasm"
    dcmp = out_dir / "decompiled.dcmp"
    _exec("wasm-opt", ["-all", str(wasm_path), "-o", str(clean)])
    _exec("wasm-decompile", [str(clean), "-o", str(dcmp)])
    text = dcmp.read_text("utf-8", "replace")
    lines = text.splitlines()
    return {
        "clean_wasm": str(clean),
        "decompiled": str(dcmp),
        "line_count": len(lines),
        "head": "\n".join(lines[:60]),
    }


def instrument_log_execution(wasm_path: Path, out_path: Path,
                             import_name: str = "log") -> Path:
    """`wasm-opt -all --log-execution=<name>`: inject a call to
    `import <name>.log_execution(i32 id)` at every function/loop entry."""
    _exec("wasm-opt", ["-all", f"--log-execution={import_name}",
                       str(wasm_path), "-o", str(out_path)])
    return out_path


def id_to_func_map(inst_wasm_path: Path, work_dir: Path,
                   import_name: str = "log") -> dict[int, int]:
    """Map each injected log id -> the defining function's index.

    Disassembles the instrumented module and walks it: the log import's own func
    index is read from its `(import "<name>" "log_execution" (func (;K;) ...))`
    line, then every `i32.const <id>` immediately followed by `call K` is bound to
    the enclosing `(func (;N;) ...)`. (binaryen prepends the one log import, so a
    defined function's index here is its index in the original module + 1.)
    """
    wat = Path(work_dir) / "inst.wat"
    wat_disassemble(inst_wasm_path, wat)

    log_idx: int | None = None
    cur_func: int | None = None
    pending_id: int | None = None
    mapping: dict[int, int] = {}
    import_marker = f'"{import_name}" "log_execution"'

    for raw in wat.read_text("utf-8", "replace").splitlines():
        line = raw.strip()
        if log_idx is None and import_marker in line and "(func (;" in line:
            log_idx = _func_index(line)
            continue
        if line.startswith("(func (;"):
            cur_func = _func_index(line)
            pending_id = None
            continue
        if line.startswith("i32.const "):
            tok = line.split()[1] if len(line.split()) > 1 else ""
            pending_id = int(tok) if tok.lstrip("-").isdigit() else None
            continue
        if line.startswith("call ") and pending_id is not None and log_idx is not None:
            target = line.split()[1]
            if target.isdigit() and int(target) == log_idx and cur_func is not None:
                mapping[pending_id] = cur_func
            pending_id = None
            continue
        pending_id = None
    return mapping


def _func_index(line: str) -> int | None:
    """Extract N from a `(func (;N;) ...)` / import func comment."""
    marker = "(;"
    i = line.find(marker)
    if i < 0:
        return None
    j = line.find(";)", i)
    if j < 0:
        return None
    tok = line[i + len(marker):j]
    return int(tok) if tok.isdigit() else None
