"""Bubblewrap execution sandbox for running untrusted targets.

Skips cleanly where bwrap or unprivileged user namespaces aren't available (some
CI/containers). The isolation guarantee that matters — no network unless asked —
is checked by proving a socket connect fails inside the default sandbox and the
process still runs.
"""
from __future__ import annotations

import shutil

import pytest

from chimera.dynamic import sandbox

if not sandbox.available():
    pytest.skip("bwrap not installed", allow_module_level=True)


def _probe():
    # a run that confirms the sandbox actually executes something
    return sandbox.run_sandboxed(["/bin/echo", "hello-sbx"], timeout=15)


if _probe().get("error") or not _probe().get("ran"):
    pytest.skip("bwrap present but unprivileged userns unavailable here",
                allow_module_level=True)


def test_runs_and_captures_stdout():
    r = sandbox.run_sandboxed(["/bin/echo", "hello-sbx"], timeout=15)
    assert r["ran"] and r["returncode"] == 0
    assert r["stdout"].strip() == "hello-sbx"


def test_network_off_by_default():
    # a TCP connect must fail with no network in the sandbox namespace. Use bash
    # /dev/tcp (outside $HOME, so not shadowed by the tmpfs) — no interpreter deps.
    if not shutil.which("bash"):
        pytest.skip("bash needed for the /dev/tcp probe")
    probe = ("exec 3<>/dev/tcp/1.1.1.1/53 && echo NET_OK || echo NET_BLOCKED")
    r = sandbox.run_sandboxed(["/bin/bash", "-c", probe], timeout=20)
    assert r["ran"], r
    assert "NET_BLOCKED" in r["stdout"], r["stdout"]


def test_workspace_persists_across_runs(tmp_path):
    # a persistent workspace = free step-by-step control: state written in one
    # run is visible in the next (and lands on the host workspace dir).
    ws = tmp_path / "ws"
    r1 = sandbox.run_sandboxed(
        ["/bin/bash", "-c", "echo kept > $HOME/m.txt"], workspace=str(ws), timeout=15)
    assert r1["ran"] and r1["returncode"] == 0
    r2 = sandbox.run_sandboxed(
        ["/bin/bash", "-c", "cat $HOME/m.txt"], workspace=str(ws), timeout=15)
    assert r2["stdout"].strip() == "kept"
    assert (ws / "m.txt").read_text().strip() == "kept"   # persisted on host


def test_missing_bwrap_reports_error(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    r = sandbox.run_sandboxed(["/bin/echo", "x"])
    assert r["ran"] is False and "bwrap" in (r["error"] or "")


def test_argv_is_a_list_never_shell(monkeypatch):
    seen = {}
    real = sandbox.subprocess.run
    def spy(args, **kw):
        seen["args"] = args
        return real(["/bin/true"], capture_output=True)
    monkeypatch.setattr(sandbox.subprocess, "run", spy)
    sandbox.run_sandboxed(["/bin/echo", "hi"])
    assert isinstance(seen["args"], list) and seen["args"][0] == "bwrap"
