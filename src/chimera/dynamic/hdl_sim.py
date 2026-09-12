"""Verilog simulation oracle — the HDL analogue of run_under_wine.

A hardware-description-language target (a Verilog/SystemVerilog IP block, a CTF
"reverse this core" challenge) is solved by *running* it: compile the design +
its testbench with Icarus Verilog and read what the testbench `$display`s. chimera
had no HDL path at all; this shells out to `iverilog`/`vvp` and captures stdout,
turning a simulation into a one-call oracle.

`iverilog`/`vvp` are external. They may be on PATH (a normal `apt install
iverilog`), or supplied explicitly — a rootless `dpkg-deb -x` extract works when
sudo isn't available, by passing the extracted `iverilog`/`vvp` paths, its `ivl`
backend via `extra_flags=('-B', '<dir>')`, and `env={'LD_LIBRARY_PATH': ...}`.
Without a usable toolchain this returns a clear "not available" result.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _resolve(tool: str) -> str | None:
    """Accept an explicit path (that exists) or resolve `tool` on PATH."""
    if os.sep in tool:                       # explicit path
        return tool if Path(tool).exists() else None
    return shutil.which(tool)


def iverilog_available(iverilog: str = "iverilog", vvp: str = "vvp") -> bool:
    return _resolve(iverilog) is not None and _resolve(vvp) is not None


def hdl_sim(sources, *, top: str | None = None,
            extra_flags: tuple[str, ...] = ("-g2012",),
            vvp_flags: tuple[str, ...] = (),
            iverilog: str = "iverilog", vvp: str = "vvp",
            env: dict | None = None, timeout: int = 120,
            workdir: str | None = None) -> dict:
    """Compile `sources` with iverilog and run the result under vvp.

    `sources` is a list of .v file paths; `top` is the top module to elaborate
    (`iverilog -s`). Returns whether it compiled, the vvp return code, and the
    captured stdout/stderr — the testbench's `$display` output is the answer.
    """
    iv = _resolve(iverilog)
    vp = _resolve(vvp)
    if iv is None or vp is None:
        return {"available": False,
                "error": "iverilog/vvp not found — `apt install iverilog`, "
                         "or pass explicit iverilog=/vvp= paths."}
    srcs = [str(s) for s in sources]
    if not srcs:
        return {"available": True, "error": "no source files given"}
    missing = [s for s in srcs if not Path(s).exists()]
    if missing:
        return {"available": True, "error": f"source(s) not found: {missing}"}

    run_env = {**os.environ, **(env or {})}
    wd = workdir or tempfile.mkdtemp(prefix="chimera_hdl_")
    out = str(Path(wd) / "a.out")
    compile_cmd = [iv, *extra_flags, *(["-s", top] if top else []), "-o", out, *srcs]
    try:
        c = subprocess.run(compile_cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout, env=run_env)
    except subprocess.TimeoutExpired:
        return {"available": True, "compiled": False, "error": "iverilog timed out",
                "compile_cmd": " ".join(compile_cmd)}
    if c.returncode != 0:
        return {"available": True, "compiled": False,
                "compile_stderr": c.stderr[-4000:], "compile_cmd": " ".join(compile_cmd),
                "error": f"iverilog failed (rc={c.returncode})"}

    run_cmd = [vp, *vvp_flags, out]
    try:
        r = subprocess.run(run_cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout, env=run_env)
    except subprocess.TimeoutExpired:
        return {"available": True, "compiled": True, "error": "vvp timed out",
                "run_cmd": " ".join(run_cmd)}
    return {
        "available": True, "compiled": True, "returncode": r.returncode,
        "stdout": r.stdout, "stderr": r.stderr[-4000:],
        "compile_cmd": " ".join(compile_cmd), "run_cmd": " ".join(run_cmd),
    }
