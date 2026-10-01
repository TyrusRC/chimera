"""Ghidra headless adapter — deep decompilation, P-Code, type recovery, FidDb."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class GhidraAdapter(BackendAdapter):
    def __init__(self, ghidra_home: str | None = None, max_mem: str = "4g"):
        self._ghidra_home_override = ghidra_home
        self._max_mem = max_mem
        self._temp_dirs: list[str] = []

    def name(self) -> str:
        return "ghidra"

    def is_available(self) -> bool:
        return self._ghidra_home is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "dex", "fat", "dylib"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 10
        mem = max(2048, int(size_mb * 40))
        seconds = max(30, int(size_mb * 5))
        return ResourceRequirement(memory_mb=mem, category=ToolCategory.HEAVY, estimated_seconds=seconds)

    @property
    def _ghidra_home(self) -> Optional[str]:
        if self._ghidra_home_override:
            return self._ghidra_home_override
        env = os.environ.get("GHIDRA_HOME")
        if env and Path(env).exists():
            return env
        candidates = ["/opt/ghidra", "/usr/local/ghidra", Path.home() / "ghidra"]
        for c in candidates:
            p = Path(c)
            if p.exists() and (p / "support" / "analyzeHeadless").exists():
                return str(p)
            if p.parent.exists():
                for child in sorted(p.parent.glob("ghidra_*"), reverse=True):
                    if (child / "support" / "analyzeHeadless").exists():
                        return str(child)
        return None

    @property
    def _analyze_headless(self) -> str:
        home = self._ghidra_home
        if not home:
            raise RuntimeError("Ghidra not found. Set GHIDRA_HOME environment variable.")
        path = Path(home) / "support" / "analyzeHeadless"
        if not path.exists():
            path = Path(home) / "support" / "analyzeHeadless.bat"
        return str(path)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        project_dir = options.get("project_dir")
        if project_dir is None:
            project_dir = tempfile.mkdtemp(prefix="chimera_ghidra_")
            self._temp_dirs.append(project_dir)
        project_name = f"chimera_{Path(binary_path).stem}"
        output_dir = Path(project_dir) / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        analysis_timeout = int(options.get("analysis_timeout", 300))
        post_script = Path(__file__).resolve().parent.parent / "ghidra_scripts"

        # mode == "decompile": decompile ONE function (options["address"]) via
        # DecompileOne.java — the standalone-Ghidra `pdg`-equivalent backend used
        # when r2ghidra can't be built; otherwise export the whole program.
        decompile_mode = options.get("mode") == "decompile"
        post_script_name = "DecompileOne.java" if decompile_mode else "ExportFunctions.java"

        # `-Xmx` is a JVM flag, not a Ghidra CLI flag — pass it via
        # GHIDRA_JVM_ARGS, otherwise analyzeHeadless aborts with
        # `InvalidInputException: Bad argument: -Xmx4g`.
        cmd = [
            self._analyze_headless, project_dir, project_name,
            "-import", binary_path, "-overwrite",
            "-max-cpu", "2",
            "-analysisTimeoutPerFile", str(analysis_timeout),
            "-scriptPath", str(post_script),
            "-postScript", post_script_name,
        ]
        if decompile_mode:
            # Pass out-dir + address as script ARGS (GHIDRA_JVM_ARGS -D props are
            # not reliably forwarded to the script JVM across Ghidra versions).
            cmd += [str(output_dir), str(options["address"])]
        processor = options.get("processor")
        if processor:
            cmd.extend(["-processor", processor])

        # Ghidra needs a writable HOME for its config dir
        # (~/.config/ghidra/<version>). In containers run with --user
        # <uid>:<gid> the inherited HOME may be `/` (unwritable), which makes
        # Ghidra abort during startup with `Failed to create directory`. Same
        # mitigation we use in the jadx adapter: substitute a writable path.
        env = os.environ.copy()
        jvm = f"-Xmx{self._max_mem} -Dchimera.out.dir={output_dir}"
        if decompile_mode:
            jvm += f" -Dchimera.decompile.addr={options['address']}"
        env["GHIDRA_JVM_ARGS"] = jvm
        home = env.get("HOME")
        if not home or not os.access(home, os.W_OK):
            ghidra_home_dir = Path(project_dir) / "ghidra_home"
            ghidra_home_dir.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(ghidra_home_dir)

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
        )
        # Ghidra's own -analysisTimeoutPerFile doesn't cover JVM startup/teardown
        # hangs. Wrap in an outer wait (analysis budget + a startup margin) and
        # kill a wedged process so it can't hold the heavy resource slot until
        # the engine-level 1800 s timeout.
        outer_timeout = analysis_timeout + int(options.get("startup_margin", 600))
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=outer_timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:  # noqa: BLE001
                pass
            return {
                "return_code": -1,
                "project_dir": project_dir,
                "output_dir": str(output_dir),
                "error": f"ghidra timed out after {outer_timeout}s (killed)",
            }

        result = {
            "return_code": proc.returncode,
            "project_dir": project_dir,
            "output_dir": str(output_dir),
        }
        for output_file in output_dir.glob("*.json"):
            try:
                result[output_file.stem] = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                result[output_file.stem] = output_file.read_text()
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        if decompile_mode:
            one = result.get("decompile_one")
            if isinstance(one, dict) and one.get("ok"):
                code = one.get("code", "")
                return {"ok": True, "backend": "ghidra",
                        "address": one.get("address", options["address"]),
                        "code": code, "lines": code.count("\n") + 1}
            err = one.get("error") if isinstance(one, dict) else None
            return {"ok": False, "backend": "ghidra", "address": options["address"],
                    "error": err or result.get("error") or "ghidra produced no decompilation"}
        return result

    async def cleanup(self) -> None:
        for d in self._temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._temp_dirs.clear()
