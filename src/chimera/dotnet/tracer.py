"""Run a Windows .NET assembly on Linux and trace named methods at runtime.

Pipeline:
  1. Confirm the target is a managed PE and pick an installed Core runtime.
  2. Write a runtimeconfig shim next to a private copy of the assembly.
  3. Build the Harmony tracer harness (once, cached), then neutralize the
     exec-stack requirement on its bundled MonoMod helper so it loads on
     hardened kernels.
  4. Run the harness against the assembly, hooking the requested methods,
     and parse the JSONL trace it writes.

Harmony detours JIT-compiled native code, not on-disk IL, so a runtime
method-integrity check that hashes the IL image does not observe the hooks
— which is what lets this trace VM-protected, anti-tamper'd validators that
defeat static devirtualization.

Everything here degrades to a clear "unavailable" result when the .NET SDK
is missing; nothing in it is required for the rest of chimera.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from chimera.dotnet.elf_stack import clear_exec_stack_requirement
from chimera.dotnet.runtimeconfig import build_runtimeconfig

logger = logging.getLogger(__name__)

_HARNESS_SRC = Path(__file__).parent / "harness"
_RUNTIME_RE = re.compile(r"^Microsoft\.NETCore\.App (\d+\.\d+\.\d+)", re.MULTILINE)


@dataclass
class TraceResult:
    available: bool
    calls: list[dict] = field(default_factory=list)
    hooks_installed: int = 0
    error: str | None = None

    def byte_values(self) -> list[tuple[str, str, str]]:
        """Every byte[] seen, as (method, ascii, hex) — the useful payloads."""
        out = []
        for c in self.calls:
            for role, val in (("result", c.get("result")), *(
                    ("arg", a) for a in c.get("args", []))):
                if isinstance(val, dict) and val.get("type") == "byte[]":
                    out.append((c.get("method", "?"), val.get("ascii", ""),
                                val.get("hex", "")))
        return out

    def strings_seen(self) -> list[tuple[str, str]]:
        """Every string argument/return, as (method, value)."""
        out = []
        for c in self.calls:
            for val in (c.get("result"), *c.get("args", [])):
                if isinstance(val, dict) and val.get("type") == "string":
                    out.append((c.get("method", "?"), val.get("value", "")))
        return out


def dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


def installed_core_runtime() -> str | None:
    """Newest installed Microsoft.NETCore.App version, or None."""
    if not dotnet_available():
        return None
    try:
        out = subprocess.run(["dotnet", "--list-runtimes"], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    versions = _RUNTIME_RE.findall(out)
    if not versions:
        return None
    return sorted(versions, key=lambda v: [int(x) for x in v.split(".")])[-1]


def _neutralize_harness_exec_stack(build_dir: Path) -> int:
    """Patch every Harmony/MonoMod DLL that embeds an exec-stack ELF helper."""
    patched = 0
    for dll in build_dir.rglob("*.dll"):
        try:
            blob = dll.read_bytes()
        except OSError:
            continue
        if b"\x7fELF" not in blob:
            continue
        try:
            new_blob, changes = clear_exec_stack_requirement(blob)
        except ValueError:
            continue
        if changes:
            dll.write_bytes(new_blob)
            patched += changes
            logger.debug("neutralized exec-stack in %s (%d)", dll.name, changes)
    return patched


def build_harness(work_dir: Path) -> Path | None:
    """Build the tracer harness into `work_dir`; return the built dll path."""
    if not dotnet_available():
        return None
    src = work_dir / "harness_src"
    if src.exists():
        shutil.rmtree(src)
    shutil.copytree(_HARNESS_SRC, src)
    out = work_dir / "harness_bin"
    try:
        proc = subprocess.run(
            ["dotnet", "build", str(src / "tracer.csproj"),
             "-c", "Release", "-o", str(out), "--nologo", "-v", "q"],
            capture_output=True, text=True, timeout=600,
            env=_dotnet_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("harness build failed to start: %s", exc)
        return None
    if proc.returncode != 0:
        logger.warning("harness build failed: %s", proc.stdout[-500:] + proc.stderr[-500:])
        return None
    _neutralize_harness_exec_stack(out)
    dll = out / "chimera_dotnet_tracer.dll"
    return dll if dll.exists() else None


def trace(assembly: Path, methods: list[str], *, stdin_line: str = "",
          work_dir: Path, timeout: int = 180) -> TraceResult:
    """Trace `methods` in `assembly`, driving its entry point once.

    Returns a TraceResult; `available=False` if the .NET SDK/runtime is
    missing or the harness could not be built.
    """
    assembly = Path(assembly)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    runtime = installed_core_runtime()
    if runtime is None:
        return TraceResult(available=False, error="no .NET Core runtime installed")

    harness = build_harness(work_dir)
    if harness is None:
        return TraceResult(available=False, error="could not build tracer harness")

    # Private copy of the target plus its runtimeconfig shim.
    target = work_dir / assembly.name
    shutil.copy(assembly, target)
    target.with_suffix(target.suffix + ".config").unlink(missing_ok=True)
    (work_dir / (assembly.stem + ".runtimeconfig.json")).write_text(
        build_runtimeconfig(runtime))

    trace_out = work_dir / "trace.jsonl"
    try:
        subprocess.run(
            ["dotnet", str(harness), str(target), str(trace_out),
             stdin_line, *methods],
            capture_output=True, text=True, timeout=timeout,
            env=_dotnet_env(),
        )
    except subprocess.TimeoutExpired:
        return TraceResult(available=True, error="trace timed out")
    except (OSError, subprocess.SubprocessError) as exc:
        return TraceResult(available=True, error=f"trace failed: {exc}")

    return _parse_trace(trace_out)


def _parse_trace(trace_out: Path) -> TraceResult:
    result = TraceResult(available=True)
    if not trace_out.exists():
        result.error = "harness produced no trace"
        return result
    for line in trace_out.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = rec.get("event")
        if event == "call":
            result.calls.append(rec)
        elif event == "hooks_installed":
            result.hooks_installed = rec.get("count", 0)
        elif event in ("entrypoint_threw",):
            # Not fatal — a wrong input path often throws after the hook fired.
            logger.debug("entrypoint threw: %s", rec.get("error"))
    return result


def _dotnet_env() -> dict:
    """Full environment for a dotnet subprocess.

    Inherits the parent env — dotnet needs HOME for its config dir — and
    only layers on the quiet flags plus the user tool path.
    """
    import os
    env = dict(os.environ)
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["DOTNET_NOLOGO"] = "1"
    tools = str(Path.home() / ".dotnet" / "tools")
    if tools not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + ":" + tools
    return env
