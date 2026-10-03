"""Go-WASM dynamic oracle + execution tracer (the `run_under_wine` analogue).

A Go module compiled to wasm exports only `run/resume/getsp`; the function you
actually want to call (e.g. `check`) is published at run time with
`js.Global().Set("check", …)`, so it can only be reached by *running* the module
under the Go JS runtime glue (`wasm_exec.js`). This drives it headless under
Node:

* :func:`run_oracle` — load the glue, instantiate with ``go.importObject``,
  ``go.run(instance)`` **without awaiting** (Go's ``main`` blocks to keep the
  JS callbacks alive), then call the exported function with each input and
  capture the return. The black-box oracle a validator-style target needs.
* :func:`trace` — instrument the module with ``--log-execution`` (binaryen),
  run it the same way with a ``log.log_execution`` import that records ids, and
  return the ordered id subtree each input executed, mapped to function indices.
  "Which functions did input X hit" — what locates the real check routine.

Node is the only runtime dependency; the module is never run with network or FS
access beyond reading its own files.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_TIMEOUT = 300


class WasmOracleError(RuntimeError):
    pass


def node_available() -> bool:
    return shutil.which("node") is not None


def find_wasm_exec_js(wasm_path: Path) -> Path | None:
    """Locate the Go runtime glue beside the module (as Chrome/popup ships it)."""
    sib = Path(wasm_path).resolve().parent / "wasm_exec.js"
    return sib if sib.is_file() else None


def _run_node(script: str, work_dir: Path) -> str:
    node = shutil.which("node")
    if not node:
        raise WasmOracleError("node not found on PATH — needed to run Go-WASM")
    harness = work_dir / "_chimera_harness.js"
    harness.write_text(script)
    try:
        proc = subprocess.run(
            [node, str(harness)], cwd=str(work_dir), timeout=_TIMEOUT,
            capture_output=True, text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise WasmOracleError(f"node harness timed out after {_TIMEOUT}s") from exc
    if proc.returncode != 0:
        raise WasmOracleError(
            f"node harness failed (rc={proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[:600]}")
    return proc.stdout


# The generated harness reads a JSON job file {wasm, wasm_exec, export, inputs,
# settle_ms, trace}. One template serves both the plain oracle and the tracer;
# `trace` toggles the log import + id collection. `go.run` is intentionally not
# awaited.
_HARNESS = r"""
'use strict';
globalThis.require = require;
const fs = require('fs');
const job = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = [];
(async () => {
  let imports;
  if (job.wasm_exec) {
    require(job.wasm_exec);           // defines globalThis.Go
    const go = new Go();
    imports = Object.assign({}, go.importObject);
    if (job.trace) imports.log = { log_execution: (id) => events.push(id) };
    var _go = go;
  } else {
    imports = {};
    if (job.trace) imports.log = { log_execution: (id) => events.push(id) };
  }
  let events = [];
  const bytes = fs.readFileSync(job.wasm);
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  if (typeof _go !== 'undefined') {
    _go.run(instance);                // NOT awaited: main() blocks to keep callbacks alive
    await new Promise(r => setTimeout(r, job.settle_ms || 150));
  }
  const fn = (typeof _go !== 'undefined')
    ? globalThis[job.export]
    : (instance.exports[job.export] || globalThis[job.export]);
  if (typeof fn !== 'function') {
    console.log(JSON.stringify({ error: 'export not callable: ' + job.export,
                                 typeof: typeof fn,
                                 exports: Object.keys(instance.exports) }));
    process.exit(3);
  }
  for (const inp of job.inputs) {
    if (job.trace) events = [];
    let res, err = null;
    try { res = fn(inp); } catch (e) { err = (e && e.message) || String(e); }
    const rec = { input: inp, result: (res === undefined ? null : res), error: err };
    if (job.trace) {
      const seen = new Set(); const order = [];
      for (const id of events) if (!seen.has(id)) { seen.add(id); order.push(id); }
      rec.total_events = events.length;
      rec.uniq_ids = order;
    }
    out.push(rec);
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
})().catch(e => { console.error('FATAL', e && e.stack || e); process.exit(1); });
"""


def _job_results(wasm_path: Path, *, export: str, inputs: list[str],
                 wasm_exec: Path | None, trace: bool, settle_ms: int,
                 work_dir: Path) -> list[dict]:
    job = {
        "wasm": str(Path(wasm_path).resolve()),
        "wasm_exec": str(Path(wasm_exec).resolve()) if wasm_exec else None,
        "export": export,
        "inputs": inputs,
        "trace": trace,
        "settle_ms": settle_ms,
    }
    job_file = work_dir / "_chimera_job.json"
    job_file.write_text(json.dumps(job))
    script = _HARNESS.replace("process.argv[2]", json.dumps(str(job_file)))
    raw = _run_node(script, work_dir)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WasmOracleError(f"harness produced non-JSON output: {raw[:300]}") from exc


def run_oracle(wasm_path: Path, inputs: list[str], *, export: str = "check",
               go: bool | None = None, wasm_exec: Path | None = None,
               settle_ms: int = 150, work_dir: Path | None = None) -> dict:
    """Run the module headless and call `export(input)` for each input.

    `go=None` auto-detects Go by the sibling `wasm_exec.js`. Returns
    ``{"export": …, "go": bool, "results": [{input, result, error}, …]}``.
    """
    wasm_path = Path(wasm_path)
    if go is None:
        go = find_wasm_exec_js(wasm_path) is not None
    if go and wasm_exec is None:
        wasm_exec = find_wasm_exec_js(wasm_path)
        if wasm_exec is None:
            raise WasmOracleError(
                "Go-WASM run needs wasm_exec.js (place it beside the module or "
                "pass wasm_exec=…)")
    with _work(work_dir) as wd:
        results = _job_results(wasm_path, export=export, inputs=list(inputs),
                               wasm_exec=wasm_exec if go else None, trace=False,
                               settle_ms=settle_ms, work_dir=wd)
    return {"export": export, "go": bool(go), "results": results}


def trace(wasm_path: Path, inputs: list[str], *, export: str = "check",
          go: bool | None = None, wasm_exec: Path | None = None,
          settle_ms: int = 200, top: int = 25,
          work_dir: Path | None = None) -> dict:
    """Instrument + run: return the executed function subtree for each input.

    Builds an instrumented copy (binaryen `--log-execution`), runs the oracle
    collecting ordered log ids, and maps ids -> function indices. For each input
    returns the unique executed function indices, highest-index-first (Go compiles
    the `main` package last, so the real app functions cluster at the top).
    """
    from chimera.adapters import wabt

    wasm_path = Path(wasm_path)
    if go is None:
        go = find_wasm_exec_js(wasm_path) is not None
    if go and wasm_exec is None:
        wasm_exec = find_wasm_exec_js(wasm_path)
        if wasm_exec is None:
            raise WasmOracleError("Go-WASM trace needs wasm_exec.js beside the module")
    with _work(work_dir) as wd:
        inst = wabt.instrument_log_execution(wasm_path, wd / "inst.wasm")
        id2func = wabt.id_to_func_map(inst, wd)
        results = _job_results(inst, export=export, inputs=list(inputs),
                               wasm_exec=wasm_exec if go else None, trace=True,
                               settle_ms=settle_ms, work_dir=wd)
    for rec in results:
        ids = rec.get("uniq_ids") or []
        funcs = sorted({id2func[i] for i in ids if i in id2func}, reverse=True)
        rec["func_indices"] = funcs
        rec["top_funcs"] = funcs[:top]
        rec.pop("uniq_ids", None)
    return {"export": export, "go": bool(go),
            "log_points": len(id2func), "results": results}


class _work:
    """Context manager: use `work_dir` if given, else a self-cleaning tempdir."""

    def __init__(self, work_dir: Path | None):
        self._given = work_dir
        self._tmp: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> Path:
        if self._given is not None:
            p = Path(self._given)
            p.mkdir(parents=True, exist_ok=True)
            return p
        self._tmp = tempfile.TemporaryDirectory(prefix="chimera_wasm_")
        return Path(self._tmp.name)

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
