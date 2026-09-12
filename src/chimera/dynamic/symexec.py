"""Symbolic execution — find the input that drives a binary to a target state.

The crackme / keygen / Flare-On endgame: a check compares your input against a
constraint and prints SUCCESS (or jumps to a "win" address). Instead of
hand-inverting the arithmetic, let angr explore paths and let its constraint
solver hand back the input that reaches the target and avoids the failures. This
complements `pathfind` (BFS over an ALREADY-recovered FSM) and `emulate_function`
(runs one CHOSEN path) — neither can discover an unknown input; angr can.

angr is optional (`pip install angr`) and its API is fluid, so — like the
oxidizer adapter — everything is guarded and degrades to available:false rather
than raising. Read-only; loads with auto_load_libs=False and bounds the search
by time and state count.
"""
from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


def _try_import_angr():
    try:
        import angr  # type: ignore[import-not-found]
        import claripy  # noqa: F401
        return angr
    except Exception:
        return None


def angr_available() -> bool:
    return _try_import_angr() is not None


def solve_input(path: str, *, find=None, avoid=None, find_stdout: str | None = None,
                avoid_stdout: str | None = None, stdin_len: int | None = None,
                sym_argv: list[int] | None = None, timeout_s: int = 120,
                max_active: int = 200) -> dict:
    """Search for an input that reaches `find` (an address or a stdout string).

    Provide a target as either `find` (hex address / int of the win block) or
    `find_stdout` (a string the winning state must have printed), optionally with
    `avoid` addresses / `avoid_stdout`. The symbolic input is `stdin_len` bytes of
    stdin and/or `sym_argv` (a list of byte-lengths for symbolic argv entries
    after argv[0]). Returns the concrete stdin/argv that gets there.
    """
    angr = _try_import_angr()
    if angr is None:
        return {"available": False, "error": "angr not installed — pip install angr"}
    if find is None and not find_stdout:
        return {"available": True, "ok": False,
                "error": "need a target: `find` (address) or `find_stdout` (string)"}
    import claripy

    def _addr(x):
        return int(x, 16) if isinstance(x, str) else int(x)

    try:
        proj = angr.Project(path, auto_load_libs=False)
        argv = [path]
        sym = {}
        for i, n in enumerate(sym_argv or []):
            bv = claripy.BVS(f"argv{i+1}", n * 8)
            argv.append(bv)
            sym[f"argv{i+1}"] = bv
        stdin_bv = None
        if stdin_len:
            stdin_bv = claripy.BVS("stdin", stdin_len * 8)
            state = proj.factory.full_init_state(
                args=argv, stdin=angr.SimFileStream(name="stdin", content=stdin_bv,
                                                    has_end=False))
        else:
            state = proj.factory.full_init_state(args=argv)

        find_pred = _addr(find) if find is not None else \
            (lambda s: find_stdout.encode() in s.posix.dumps(1))
        avoid_addrs = [_addr(a) for a in (avoid or [])]
        if avoid_stdout:
            avoid_pred = lambda s: avoid_stdout.encode() in s.posix.dumps(1)
            avoid_arg = avoid_pred if not avoid_addrs else \
                (lambda s: s.addr in avoid_addrs or avoid_pred(s))
        else:
            avoid_arg = avoid_addrs or None

        simgr = proj.factory.simulation_manager(state)
        start = time.time()
        # manual stepping so we can enforce a wall-clock budget angr.explore lacks
        while simgr.active and not simgr.found:
            simgr.explore(find=find_pred, avoid=avoid_arg, num_find=1, n=1)
            if simgr.found or time.time() - start > timeout_s:
                break
            if len(simgr.active) > max_active:
                simgr.active = simgr.active[:max_active]
        if not simgr.found:
            return {"available": True, "ok": False,
                    "error": f"no path to target within {timeout_s}s "
                             f"({len(simgr.active)} active, {len(simgr.deadended)} dead)"}
        s = simgr.found[0]
        out = {"available": True, "ok": True, "target": (hex(_addr(find)) if find is not None
                                                          else f"stdout~{find_stdout!r}")}
        if stdin_bv is not None:
            data = s.posix.dumps(0)
            out["stdin"] = {"hex": data.hex(), "ascii": data.decode("latin-1")}
        argv_out = []
        for name, bv in sym.items():
            val = s.solver.eval(bv, cast_to=bytes)
            argv_out.append({"name": name, "hex": val.hex(), "ascii": val.decode("latin-1")})
        if argv_out:
            out["argv"] = argv_out
        if not stdin_bv and not argv_out:
            out["note"] = "reached target but no symbolic input was declared (stdin_len/sym_argv)"
        return out
    except Exception as exc:  # angr's API is fluid — never raise into the handler
        return {"available": True, "ok": False, "error": f"angr error: {type(exc).__name__}: {exc}"}
