"""Run a Windows PE on this Linux box under Wine as a dynamic RE oracle.

When a target resists static analysis, executing it and observing a signal
(stdout, a decrypted file it drops, the text of a blocking MessageBox) is often
far cheaper than hand-tracing. This packages the `dynamic-analysis` skill into
one call: an isolated throwaway WINEPREFIX, quiet debug channels, headless
console or Xvfb GUI, and an optional best-effort scan of the process memory for
an answer that never reaches stdout.

Safety: this executes an external binary, so we build an argv LIST (never a
shell string / shell=True), validate the exe exists, always run in an isolated
scratch prefix (never the project tree), and enforce a timeout.

Host facts (this box, 2026-09): wine is unified WoW64 — do NOT set
WINEARCH=win32. 32-bit PE32 support needs wine32:i386 + a fresh prefix. A
console app wants no DISPLAY (stdout carries output; decoy MessageBox/
ShellExecute fail harmlessly); a GUI app whose answer is in a window wants
Xvfb, then scan memory rather than screenshot.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time

logger = logging.getLogger(__name__)

_DLL_OVERRIDES = "mscoree,mshtml=d"   # kill the mono/gecko install nag


def _needle_variants(needle: str | bytes) -> list[bytes]:
    """Both byte encodings a Win32 program might hold the string in: narrow
    (utf-8/ascii) and wide (utf-16-le, used by every `...W` API). De-duped."""
    if isinstance(needle, bytes):
        variants = [needle]
    else:
        variants = [needle.encode("utf-8"), needle.encode("utf-16-le")]
    out: list[bytes] = []
    for v in variants:
        if v and v not in out:
            out.append(v)
    return out


def _wine_env(prefix: str, *, headless: bool, extra: dict | None = None) -> dict:
    """Environment for an isolated, quiet Wine run. Drops DISPLAY for a headless
    console run so decoy GUI calls fail harmlessly instead of blocking."""
    env = dict(os.environ)
    env["WINEPREFIX"] = prefix
    env["WINEDEBUG"] = "-all"
    env["WINEDLLOVERRIDES"] = _DLL_OVERRIDES
    if headless:
        env.pop("DISPLAY", None)
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


def _parse_maps(pid: int) -> list[tuple[int, int]]:
    """Readable (start, end) byte ranges from /proc/<pid>/maps."""
    ranges: list[tuple[int, int]] = []
    try:
        with open(f"/proc/{pid}/maps", "r") as fh:
            for line in fh:
                addr, _, rest = line.partition(" ")
                perms = rest[:4]
                if "r" not in perms:
                    continue
                lo, _, hi = addr.partition("-")
                try:
                    ranges.append((int(lo, 16), int(hi, 16)))
                except ValueError:
                    continue
    except OSError:
        pass
    return ranges


def scan_pid_memory(pid: int, needles: list[bytes]) -> dict[bytes, list[int]]:
    """Best-effort search of a live process's readable memory for each needle.

    A blocking MessageBox keeps its text resident, so this pulls a GUI answer
    that never touches stdout. Every read is guarded — regions race with the
    target and many are unreadable. Returns absolute virtual-address offsets.

    NOTE (ceiling): best-effort only; a region can be unmapped mid-read, and a
    very large address space is scanned linearly.
    """
    hits: dict[bytes, list[int]] = {n: [] for n in needles}
    if not needles:
        return hits
    try:
        mem = open(f"/proc/{pid}/mem", "rb", 0)
    except OSError:
        return hits
    try:
        for lo, hi in _parse_maps(pid):
            size = hi - lo
            if size <= 0 or size > 256 * 1024 * 1024:   # skip absurd regions
                continue
            try:
                mem.seek(lo)
                chunk = mem.read(size)
            except (OSError, ValueError, OverflowError):
                continue
            for n in needles:
                start = 0
                while True:
                    idx = chunk.find(n, start)
                    if idx < 0:
                        break
                    hits[n].append(lo + idx)
                    start = idx + 1
    finally:
        mem.close()
    return hits


def run_under_wine(
    exe: str,
    args: tuple | list = (),
    *,
    prefix: str | None = None,
    headless: bool = True,
    xvfb: bool = False,
    timeout: float = 30,
    memory_scan: str | None = None,
    stdin: bytes | None = None,
    env_extra: dict | None = None,
) -> dict:
    """Execute a Windows PE under Wine in an isolated prefix; capture output.

    Returns a dict:
      ran, returncode, stdout, stderr, timed_out, wineprefix,
      memory_hits ({needle_hex: [offsets]} | None), error (str | None).

    Never raises for the common failure modes (wine absent, exe missing,
    timeout) — reports them in the dict. The scratch WINEPREFIX is left on disk
    (analysts inspect files/ADS the target wrote); its path is reported.
    """
    result = {
        "ran": False, "returncode": None, "stdout": "", "stderr": "",
        "timed_out": False, "wineprefix": prefix or "", "memory_hits": None,
        "error": None,
    }

    wine = shutil.which("wine")
    if not wine:
        result["error"] = "wine not found on PATH"
        return result
    if not os.path.isfile(exe):
        result["error"] = f"exe not found: {exe}"
        return result

    created = prefix is None
    if prefix is None:
        prefix = tempfile.mkdtemp(prefix="chimera-wine-")
    result["wineprefix"] = prefix
    env = _wine_env(prefix, headless=headless and not xvfb, extra=env_extra)

    # A fresh prefix runs wineboot on first use (tens of seconds); do it once
    # up front on its own budget so it doesn't eat the target's timeout — the
    # exact trap of "first run always times out".
    if created:
        boot = shutil.which("wineboot")
        if boot:
            try:
                subprocess.run([boot, "--init"], env=env,
                               capture_output=True, timeout=max(120.0, timeout))
            except (subprocess.TimeoutExpired, OSError):
                pass  # best-effort; the run below still works, just slower

    argv: list[str] = [wine, exe, *[str(a) for a in args]]
    if xvfb:
        if shutil.which("xvfb-run"):
            argv = ["xvfb-run", "-a", *argv]
        else:
            result["error"] = "xvfb requested but xvfb-run not found on PATH"
            return result

    needles = _needle_variants(memory_scan) if memory_scan else []

    def _decode(b: bytes) -> str:
        return (b or b"").decode("utf-8", "replace")

    # No memory scan → the simple, robust capture path.
    if not needles:
        try:
            proc = subprocess.run(
                argv, env=env, capture_output=True, input=stdin,
                timeout=timeout,
            )
            result["ran"] = True
            result["returncode"] = proc.returncode
            result["stdout"] = _decode(proc.stdout)
            result["stderr"] = _decode(proc.stderr)
        except subprocess.TimeoutExpired as te:
            result["ran"] = True
            result["timed_out"] = True
            result["stdout"] = _decode(te.stdout)
            result["stderr"] = _decode(te.stderr)
        return result

    # Memory-scan path: run via Popen so we can peek /proc/<pid>/mem while the
    # target (often a blocking MessageBox) is still alive. NOTE: racy and
    # best-effort — the pid Popen sees is the wine loader, so we scan it plus
    # its children.
    hits: dict[bytes, list[int]] = {n: [] for n in needles}
    try:
        proc = subprocess.Popen(
            argv, env=env, stdin=subprocess.PIPE if stdin else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        result["error"] = f"failed to launch: {exc}"
        return result
    if stdin:
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except OSError:
            pass

    deadline = time.time() + timeout
    scanned = 0
    while proc.poll() is None and time.time() < deadline:
        if scanned < 3:                    # a few peeks while it's blocked
            for pid in _descendant_pids(proc.pid):
                for n, offs in scan_pid_memory(pid, needles).items():
                    hits[n].extend(offs)
            scanned += 1
        time.sleep(0.5)

    try:
        out, err = proc.communicate(timeout=max(0.1, deadline - time.time()))
        result["returncode"] = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        result["timed_out"] = True
    result["ran"] = True
    result["stdout"] = _decode(out)
    result["stderr"] = _decode(err)
    result["memory_hits"] = {
        n.hex(): sorted(set(o)) for n, o in hits.items() if o
    } or {}
    return result


def _descendant_pids(root: int) -> list[int]:
    """root pid plus its descendants, via /proc/<pid>/task/*/children.
    Best-effort; returns [root] if the walk fails."""
    seen = [root]
    frontier = [root]
    while frontier:
        pid = frontier.pop()
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as fh:
                kids = [int(x) for x in fh.read().split()]
        except (OSError, ValueError):
            continue
        for k in kids:
            if k not in seen:
                seen.append(k)
                frontier.append(k)
    return seen
