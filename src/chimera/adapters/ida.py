"""IDA Pro (Hex-Rays) decompiler backend — headless idat batch.

A user-selectable decompiler engine alongside r2ghidra (pdg) / radare2 (pdc).
Runs idat headless on a temp copy of the binary with a bundled IDAPython script
and returns the Hex-Rays C in the same contract as the r2 decompile path.
Degrades to a clear {ok: false} when IDA isn't installed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory
from chimera.dynamic.vm.runner import to_windows_path

_SCRIPT = Path(__file__).parent / "ida_scripts" / "decompile_one.py"


class IdaAdapter(BackendAdapter):
    def __init__(self, idat: str | None = None, timeout: int = 300):
        self._idat = idat if idat is not None else self._resolve_idat()
        self._timeout = timeout

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

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if options.get("mode") != "decompile":
            return {"ok": False, "error": "IdaAdapter supports mode=decompile only"}
        addr = options.get("address")
        if not addr:
            return {"ok": False, "error": "address required for decompile mode"}
        if self._idat is None:
            return {"ok": False, "error": "IDA not found",
                    "hint": "install IDA Pro and set IDA_PATH (dir or idat64), "
                            "or put idat64 on PATH"}
        # A Windows idat64.exe driven from WSL cannot read Linux paths — the temp
        # binary, the IDAPython script and the output file must be Windows paths
        # (translated via wslpath; they resolve to the same files over \\wsl$).
        windows = self._idat.lower().endswith(".exe")

        def host(p: str) -> str:
            return to_windows_path(p) if windows else p

        with tempfile.TemporaryDirectory(prefix="chimera_ida_") as td:
            tmpbin = Path(td) / Path(binary_path).name
            shutil.copy2(binary_path, tmpbin)
            outfile = Path(td) / "out.c"
            env = {**os.environ, "TVHEADLESS": "1",
                   "CHIMERA_IDA_ADDR": str(addr), "CHIMERA_IDA_OUT": host(str(outfile))}
            argv = [self._idat, "-A", f"-S{host(str(_SCRIPT))}", "-c", host(str(tmpbin))]
            try:
                subprocess.run(argv, env=env, timeout=self._timeout, capture_output=True)
            except subprocess.TimeoutExpired:
                return {"ok": False, "error": "ida decompile timed out"}
            except (FileNotFoundError, OSError) as e:
                return {"ok": False, "error": f"idat run failed: {e}"}
            code = outfile.read_text() if outfile.exists() else ""
        if not code.strip():
            return {"ok": False, "error": "ida produced no output",
                    "hint": "the address may not be a function, or Hex-Rays is not "
                            "licensed in this IDA install"}
        return {"ok": True, "backend": "ida-hexrays", "address": str(addr),
                "code": code, "lines": code.count("\n") + 1}

    async def cleanup(self) -> None:
        return None
