"""Host command runner for VM providers.

Resolves the hypervisor CLI — including a Windows `.exe` reachable over WSL
interop — translates WSL paths to Windows paths for the Windows-side tool, and
runs argv LISTS (never a shell string) with a hard timeout. Never raises on a
missing binary or a timeout; the caller sees it in the RunResult.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


def resolve_cli(name: str, windows_default: str | None = None) -> str | None:
    for cand in (name, name + ".exe"):
        found = shutil.which(cand)
        if found:
            return found
    if windows_default and Path(windows_default).exists():
        return windows_default
    return None


def is_wsl() -> bool:
    # Env markers are the most reliable: WSL always sets these for interop, and
    # they survive custom kernels whose /proc/version drops the "microsoft" tag
    # (e.g. a xanmod WSL2 build reads "...-WSL2-xanmod1 (clang ...)").
    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        v = Path("/proc/version").read_text().lower()
        return "microsoft" in v or "wsl" in v
    except OSError:
        return False


def to_windows_path(path: str) -> str:
    if not is_wsl():
        return path
    r = run(["wslpath", "-w", path], timeout=10)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else path


def run(argv: list[str], *, timeout: int, stdin: str | None = None) -> RunResult:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, input=stdin)
        return RunResult(p.returncode, p.stdout, p.stderr, False)
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = e.stderr or ""
        return RunResult(124, out if isinstance(out, str) else out.decode(errors="replace"),
                         err if isinstance(err, str) else err.decode(errors="replace"), True)
    except (FileNotFoundError, OSError) as e:
        return RunResult(127, "", str(e), False)
