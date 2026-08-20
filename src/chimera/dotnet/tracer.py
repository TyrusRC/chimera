"""Run a Windows .NET assembly on Linux and trace named methods at runtime.

Pipeline:
  1. Confirm the target is a managed PE and pick an installed Core runtime.
  2. Write a runtimeconfig shim next to a private copy of the assembly, and
     (when asked) compile the Win32 stub that lets a Windows-only binary run
     on Linux — its kernel32/ntdll imports no-op, which also blanks the
     anti-debug imports that share that surface.
  3. Build the Harmony tracer harness (once, cached), then neutralize the
     exec-stack requirement on its bundled MonoMod helper so it loads on
     hardened kernels.
  4. Run the harness against the assembly — hooking the requested methods and
     driving a scripted stdin through any menu to the key prompt — and parse
     the JSONL trace it writes into a TraceResult.

Harmony detours JIT-compiled native code, not on-disk IL, so a runtime
method-integrity check that hashes the IL image does not observe the hooks
— which is what lets this trace VM-protected, anti-tamper'd validators that
defeat static devirtualization.

Everything here degrades to a clear "unavailable" result when the .NET SDK
is missing; nothing in it is required for the rest of chimera.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from chimera.dotnet.elf_stack import clear_exec_stack_requirement
from chimera.dotnet.runtimeconfig import build_runtimeconfig
from chimera.dotnet.trace_result import TraceResult, parse_trace

logger = logging.getLogger(__name__)

_HARNESS_SRC = Path(__file__).parent / "harness"
_RUNTIME_RE = re.compile(r"^Microsoft\.NETCore\.App (\d+\.\d+\.\d+)", re.MULTILINE)


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


def build_win32_stub(work_dir: Path) -> Path | None:
    """Compile the Win32 stub shared library into `work_dir`.

    A Windows .NET binary calls kernel32/ntdll, absent on Linux; the stub
    exports those entry points as benign no-ops so the process runs to its
    key check. Returns the .so path, or None if no C compiler is available
    (in which case P/Invoke neutralization is simply unavailable).
    """
    src = _HARNESS_SRC / "win32_stub.c"
    if not src.exists():
        return None
    out = work_dir / "chimera_win32_stub.so"
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        logger.warning("no C compiler found; cannot build Win32 stub")
        return None
    try:
        proc = subprocess.run(
            [cc, "-shared", "-fPIC", "-o", str(out), str(src)],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Win32 stub build failed to start: %s", exc)
        return None
    if proc.returncode != 0:
        logger.warning("Win32 stub build failed: %s", proc.stderr[-500:])
        return None
    return out if out.exists() else None


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


def trace(assembly: Path, methods: list[str], *,
          stdin_lines: list[str] | None = None, neutralize_pinvoke: bool = False,
          work_dir: Path, timeout: int = 180) -> TraceResult:
    """Trace `methods` in `assembly`, driving its entry point once.

    `stdin_lines` supplies a menu-navigation script — one Console.ReadLine
    per element — to drive a menu-loop program to its key prompt.
    `neutralize_pinvoke` installs the Win32 stub so a Windows-only binary
    runs on Linux and its anti-debug imports read as clean — equivalent to
    passing the "@neutralize-pinvoke" spec in `methods`.

    Returns a TraceResult; `available=False` if the .NET SDK/runtime is
    missing or the harness could not be built.
    """
    stdin_line = "\n".join(stdin_lines or [])
    methods = list(methods)
    if neutralize_pinvoke and "@neutralize-pinvoke" not in methods:
        methods = ["@neutralize-pinvoke", *methods]
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

    env = _dotnet_env()
    if any(m == "@neutralize-pinvoke" for m in methods):
        stub = build_win32_stub(work_dir)
        if stub is not None:
            env["CHIMERA_WIN32_STUB"] = str(stub)

    trace_out = work_dir / "trace.jsonl"
    try:
        subprocess.run(
            ["dotnet", str(harness), str(target), str(trace_out),
             stdin_line, *methods],
            capture_output=True, text=True, timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        # The harness appends each call to the trace file live, so a run that
        # spins (a menu loop reprinting on stdin EOF is the common case) has
        # still written everything captured before the kill. Parse it rather
        # than throwing the recovered data away; just flag that it was cut.
        result = parse_trace(trace_out)
        result.error = "trace timed out (showing what was captured first)"
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        return TraceResult(available=True, error=f"trace failed: {exc}")

    return parse_trace(trace_out)


def _dotnet_env() -> dict:
    """Full environment for a dotnet subprocess.

    Inherits the parent env — dotnet needs HOME for its config dir — and
    only layers on the quiet flags plus the user tool path.
    """
    env = dict(os.environ)
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["DOTNET_NOLOGO"] = "1"
    tools = str(Path.home() / ".dotnet" / "tools")
    if tools not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + ":" + tools
    return env
