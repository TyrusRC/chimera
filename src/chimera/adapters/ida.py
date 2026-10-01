"""IDA Pro (Hex-Rays) decompiler/analysis backend — headless idat batch.

A user-selectable decompiler engine alongside r2ghidra (pdg) / radare2 (pdc),
plus whole-program helpers that beat r2 on PE function recovery (IDA walks
.pdata, so it finds the thousands of functions an ILT-thunked PE hides).

Optimised for iterative RE: the database is built ONCE (full auto-analysis,
`save_database`) in a per-binary cache dir keyed by sha256, so every later query
reopens that database in seconds instead of re-analysing. Modes:

  decompile  : Hex-Rays pseudo-C for one function (needs IDAPython + a licensed
               decompiler).
  functions  : every function as (addr, size, name)   — pure IDC, no Python.
  disasm     : one function's instructions                — pure IDC, no Python.
  script     : run a caller-supplied .idc/.py against the cached DB and return
               whatever it wrote to the output path — the escape hatch.

Two WSL→Windows gotchas are handled here because a bare Windows IDA is common:
  * No env vars reach a Windows idat launched from WSL, so the output path and
    address are TEMPLATED into the script (`__CHIMERA_OUT__`/`__CHIMERA_ADDR__`)
    rather than read from getenv.
  * Scripts and output on a \\wsl$ share are unreliable, so all scratch lives in
    the cache dir (keep it on a drvfs mount, e.g. /mnt/c, under WSL).
The IDC modes matter because a bare Windows IDA often has no Python configured
(`idapyswitch` finds none), which disables IDAPython but not IDC. Degrades to a
clear {ok: false} when IDA isn't installed.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory
from chimera.dynamic.vm.runner import to_windows_path

_SCRIPTS = Path(__file__).parent / "ida_scripts"
_DECOMPILE = _SCRIPTS / "decompile_one.py"
_BUILD_IDB = _SCRIPTS / "build_idb.idc"
_LIST_FUNCS = _SCRIPTS / "list_functions.idc"
_DISASM = _SCRIPTS / "disasm_one.idc"


class IdaAdapter(BackendAdapter):
    def __init__(self, idat: str | None = None, timeout: int = 300,
                 cache_dir: str | None = None):
        self._idat = idat if idat is not None else self._resolve_idat()
        self._timeout = timeout
        self._cache_dir = Path(
            cache_dir or os.environ.get("CHIMERA_IDA_CACHE")
            or (Path(tempfile.gettempdir()) / "chimera-ida-cache"))

    @staticmethod
    def _resolve_idat() -> str | None:
        exes = ("idat64", "idat", "idat64.exe", "idat.exe")
        env = os.environ.get("IDA_PATH")
        if env:
            p = Path(env)
            if p.is_file():
                return str(p)
            for exe in exes:
                if (p / exe).is_file():
                    return str(p / exe)
        for exe in exes:
            found = shutil.which(exe)
            if found:
                return found
        return None

    def name(self) -> str:
        return "ida"

    def is_available(self) -> bool:
        return self._idat is not None

    def supported_formats(self) -> list[str]:
        return ["pe", "elf", "macho"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=2048, category=ToolCategory.HEAVY,
                                   estimated_seconds=60)

    def _is_win(self) -> bool:
        return self._idat.lower().endswith(".exe")

    def _host(self, p: str) -> str:
        return to_windows_path(p) if self._is_win() else p

    @staticmethod
    def _sha16(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]

    def _run_idat(self, script: str, workbin: str, create: bool) -> str | None:
        argv = [self._idat, "-A", f"-S{self._host(script)}"]
        if create:
            # -o names the database; without it an -A batch run does not persist
            # one. The base becomes <dir>/input (IDA drops the .i64 ext), which is
            # also what a later reopen of the working binary resolves to.
            idb = str(Path(workbin).with_suffix(".i64"))
            argv += ["-c", f"-o{self._host(idb)}"]
        argv.append(self._host(workbin))
        try:
            subprocess.run(argv, env={**os.environ, "TVHEADLESS": "1"},
                           timeout=self._timeout, capture_output=True)
            return None
        except subprocess.TimeoutExpired:
            return "idat timed out"
        except (FileNotFoundError, OSError) as e:
            return f"idat run failed: {e}"

    def _ensure_db(self, binary_path: str) -> tuple[str | None, str | None]:
        """Build (once) the cached IDA database; return (workbin_path, error).

        The working copy of the binary + IDA's database files live in a cache
        dir keyed by sha256 so the caller's binary is never touched and the
        analysis is reused. The DB is the unpacked set (input.id0, …) that IDA
        reopens when idat is pointed back at the working binary.
        """
        try:
            key = self._sha16(binary_path)
        except OSError as e:
            return None, f"cannot read binary: {e}"
        d = self._cache_dir / key
        d.mkdir(parents=True, exist_ok=True)
        workbin = d / f"input{Path(binary_path).suffix or '.bin'}"
        if not workbin.exists():
            shutil.copy2(binary_path, workbin)
        if (d / "input.id0").exists():
            return str(workbin), None
        staged = d / "_build_idb.idc"
        shutil.copy2(_BUILD_IDB, staged)
        err = self._run_idat(str(staged), str(workbin), create=True)
        staged.unlink(missing_ok=True)
        if err:
            return None, err
        if not (d / "input.id0").exists():
            return None, ("IDA produced no database — check the license was "
                          "accepted (first GUI run) and idat is the text-mode binary")
        return str(workbin), None

    @staticmethod
    def _addr_literal(addr) -> str:
        s = str(addr).strip()
        return f"0x{int(s, 0) if s.lower().startswith('0x') else int(s, 16):x}"

    def _exec(self, workbin: str, script: str, addr=None) -> tuple[str, str | None]:
        """Template __CHIMERA_OUT__/__CHIMERA_ADDR__ into `script`, run it against
        the (reopened) cached DB, and return (output, error)."""
        keydir = Path(workbin).parent
        outfile = keydir / f"out_{os.getpid()}_{abs(hash(script)) & 0xffffff}.txt"
        outfile.unlink(missing_ok=True)
        out_host = self._host(str(outfile))
        is_py = script.endswith(".py")
        out_lit = out_host if is_py else out_host.replace("\\", "\\\\")
        txt = Path(script).read_text().replace("__CHIMERA_OUT__", out_lit)
        if addr is not None:
            txt = txt.replace("__CHIMERA_ADDR__", self._addr_literal(addr))
        staged = keydir / ("_run" + Path(script).suffix)
        staged.write_text(txt)
        err = self._run_idat(str(staged), workbin, create=False)
        staged.unlink(missing_ok=True)
        if err:
            return "", err
        text = outfile.read_text(errors="replace") if outfile.exists() else ""
        outfile.unlink(missing_ok=True)
        return text, None

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if self._idat is None:
            return {"ok": False, "error": "IDA not found",
                    "hint": "install IDA Pro and set IDA_PATH (dir or idat64), "
                            "or put idat64 on PATH"}
        mode = options.get("mode", "decompile")
        if mode not in ("decompile", "functions", "disasm", "script"):
            return {"ok": False, "error": f"unknown IDA mode {mode!r}"}

        workbin, err = self._ensure_db(binary_path)
        if workbin is None:
            return {"ok": False, "error": err}

        if mode == "decompile":
            addr = options.get("address")
            if not addr:
                return {"ok": False, "error": "address required for decompile mode"}
            code, err = self._exec(workbin, str(_DECOMPILE), addr)
            if err:
                return {"ok": False, "error": err}
            if not code.strip():
                return {"ok": False, "error": "ida produced no output",
                        "hint": "the address may not be a function, or Hex-Rays "
                                "is not licensed / IDAPython is not configured"}
            return {"ok": True, "backend": "ida-hexrays", "address": str(addr),
                    "code": code, "lines": code.count("\n") + 1}

        if mode == "functions":
            text, err = self._exec(workbin, str(_LIST_FUNCS))
            if err:
                return {"ok": False, "error": err}
            funcs = []
            for line in text.splitlines():
                parts = line.split("\t")
                if len(parts) == 3:
                    funcs.append({"addr": "0x" + parts[0], "size": int(parts[1]),
                                  "name": parts[2]})
            return {"ok": True, "backend": "ida", "count": len(funcs), "functions": funcs}

        if mode == "disasm":
            addr = options.get("address")
            if not addr:
                return {"ok": False, "error": "address required for disasm mode"}
            text, err = self._exec(workbin, str(_DISASM), addr)
            if err:
                return {"ok": False, "error": err}
            if not text.strip():
                return {"ok": False, "error": "no disassembly — address is not a function"}
            return {"ok": True, "backend": "ida", "address": str(addr),
                    "disasm": text, "lines": text.count("\n") + 1}

        # mode == "script": run a caller-supplied .idc/.py against the DB
        script = options.get("script")
        if not script or not Path(script).exists():
            return {"ok": False, "error": "script=<path to .idc/.py> required"}
        text, err = self._exec(workbin, str(script), options.get("address"))
        if err:
            return {"ok": False, "error": err}
        return {"ok": True, "backend": "ida", "script": script, "output": text}

    async def cleanup(self) -> None:
        return None
