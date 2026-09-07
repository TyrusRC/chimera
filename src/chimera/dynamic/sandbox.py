"""Run a program in an isolated sandbox, no root and no daemon, via bubblewrap.

Dynamic analysis means running untrusted code — a crackme, a malware sample, a
CTF binary that writes files next to itself or phones home. This confines it:
its own PID/mount/IPC/UTS namespace, network OFF by default (so a sample can't
beacon or pull a payload), a throwaway tmpfs for /tmp and $HOME, and only the
paths you bind made visible — the rest of the filesystem is read-only or hidden.
It runs on the host kernel (fast, and ptrace/`bp-dump` still work inside), unlike
a full VM; for a real Windows guest or a config that needs root (a different
`ptrace_scope`, a kernel knob) use the QEMU path documented in the sandbox skill.

Safety: build an argv LIST (never a shell string), default-deny network, confine
writes to an explicit tmpfs/rw-binds, and enforce a timeout. bubblewrap is the
`bwrap` binary (Debian/Kali: `apt install bubblewrap`); absent, we say so rather
than run unconfined.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)


def available() -> bool:
    return shutil.which("bwrap") is not None


# System directories that a program needs to run, bound read-only. We do NOT
# bind the whole host root: the analyst's home (SSH keys, ~/.claude creds),
# other users' homes, /root, and the project tree must stay invisible to an
# untrusted target — least privilege for a confinement sandbox. The caller adds
# back exactly the inputs it wants via ro_binds/rw_binds/workspace.
_SYS_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc")


def _base_args(net: bool) -> list[str]:
    args = ["bwrap"]
    for d in _SYS_DIRS:
        if os.path.exists(d):
            args += ["--ro-bind", d, d]
    args += [
        "--dev", "/dev", "--proc", "/proc",
        "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--unshare-all", "--die-with-parent", "--new-session",
    ]
    if net:
        args += ["--share-net"]
    return args


def run_sandboxed(
    argv: list[str],
    *,
    ro_binds: tuple = (),
    rw_binds: tuple = (),
    workdir: str | None = None,
    net: bool = False,
    timeout: float = 30,
    env: dict | None = None,
    stdin: bytes | None = None,
    home_tmpfs: bool = True,
    wine: bool = False,
    wineprefix: str | None = None,
    workspace: str | None = None,
) -> dict:
    """Run `argv` confined by bubblewrap; capture output.

    - network is OFF unless `net=True` (a sample can't beacon by default);
    - `/tmp` and (with `home_tmpfs`) `$HOME` are throwaway tmpfs, so writes don't
      touch the host; add `rw_binds` for paths the target may write, `ro_binds`
      for extra read-only inputs (each a "src" or "src:dst" string);
    - `workspace=<dir>` makes a PERSISTENT sandbox you drive freely: the dir is
      bound rw as `$HOME` (not a throwaway tmpfs) and is the working directory, so
      files the target drops, and a Wine prefix (defaults to `<workspace>/.wine`),
      SURVIVE across calls. Run any sequence of commands against the same
      workspace — files, prefix and state carry over — which is how you keep
      full control of a target step by step instead of one-shotting it;
    - `wine=True` runs the target under Wine in an isolated `wineprefix`
      (a scratch dir, or `<workspace>/.wine`, bound rw) with the quiet/headless env.

    Returns {ran, returncode, stdout, stderr, timed_out, error, sandbox}. Never
    raises for the common failures (bwrap missing, target missing) — reports them.
    """
    result = {"ran": False, "returncode": None, "stdout": "", "stderr": "",
              "timed_out": False, "error": None, "sandbox": "bwrap"}
    if not available():
        result["error"] = "bwrap (bubblewrap) not found on PATH"
        return result
    if not argv:
        result["error"] = "empty argv"
        return result

    args = _base_args(net)
    # Apply the throwaway $HOME tmpfs BEFORE the user binds, so an explicitly
    # bound path under $HOME (e.g. the target binary) overlays it and stays
    # visible rather than being shadowed.
    child_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    if workspace:
        # persistent, freely-driven sandbox: real dir as $HOME, state survives.
        ws = os.path.abspath(workspace)
        os.makedirs(ws, exist_ok=True)
        args += ["--bind", ws, ws]
        child_env["HOME"] = ws
        workdir = workdir or ws
        if wine and not wineprefix:
            wineprefix = os.path.join(ws, ".wine")
    else:
        home = os.path.expanduser("~")
        home = home if home != "~" else "/root"
        if home_tmpfs:
            args += ["--tmpfs", home]
            child_env["HOME"] = home
    for spec in ro_binds:
        src, _, dst = str(spec).partition(":")
        args += ["--ro-bind", src, dst or src]
    for spec in rw_binds:
        src, _, dst = str(spec).partition(":")
        args += ["--bind", src, dst or src]

    if wine:
        wp = wineprefix or tempfile.mkdtemp(prefix="chimera-sbx-wine-")
        os.makedirs(wp, exist_ok=True)
        args += ["--bind", wp, wp]
        child_env.update({
            "WINEPREFIX": wp, "WINEDEBUG": "-all",
            "WINEDLLOVERRIDES": "mscoree,mshtml=d",
        })
        result["wineprefix"] = wp
        target = ["wine", *argv]
    else:
        target = list(argv)

    if env:
        child_env.update({str(k): str(v) for k, v in env.items()})
    for k, v in child_env.items():
        args += ["--setenv", k, v]
    if workdir:
        args += ["--chdir", workdir]

    args += ["--", *target]

    def _dec(b: bytes) -> str:
        return (b or b"").decode("utf-8", "replace")

    try:
        proc = subprocess.run(args, capture_output=True, input=stdin, timeout=timeout)
        result.update(ran=True, returncode=proc.returncode,
                      stdout=_dec(proc.stdout), stderr=_dec(proc.stderr))
    except subprocess.TimeoutExpired as te:
        result.update(ran=True, timed_out=True,
                      stdout=_dec(te.stdout), stderr=_dec(te.stderr))
    except OSError as exc:
        result["error"] = f"failed to launch sandbox: {exc}"
    return result
