"""VirtualBox provider (VBoxManage) — the reference VmProvider.

Drives VBoxManage (a Windows .exe over WSL interop, or a native binary) for
snapshots, power, guest exec, and file copy. Guest exec/copy require Guest
Additions in the guest and guest credentials; the password is fed on stdin via
`--password-file -`, never on argv.
"""
from __future__ import annotations

import re

from chimera.dynamic.vm.base import ExecResult, VmInfo
from chimera.dynamic.vm.runner import resolve_cli, run, to_windows_path

_WINDOWS_DEFAULT = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
_LIST_RE = re.compile(r'^"(?P<name>.+)"\s+\{[0-9a-fA-F-]+\}\s*$')


class VirtualBoxProvider:
    name = "virtualbox"

    def __init__(self, cli: str | None = None, timeout: int = 120):
        self._cli = cli if cli is not None else resolve_cli("VBoxManage", _WINDOWS_DEFAULT)
        self._timeout = timeout

    def available(self) -> bool:
        return self._cli is not None

    def _vbm(self, *args, stdin=None, timeout=None):
        return run([self._cli, *args], timeout=timeout or self._timeout, stdin=stdin)

    def list(self) -> list[VmInfo]:
        r = self._vbm("list", "vms")
        out = []
        for line in r.stdout.splitlines():
            m = _LIST_RE.match(line.strip())
            if m:
                out.append(VmInfo(name=m.group("name"), state="unknown"))
        return out

    def snapshot(self, vm: str, name: str) -> None:
        self._vbm("snapshot", vm, "take", name)

    def revert(self, vm: str, name: str) -> None:
        # poweroff first if running; restore is only valid on a stopped VM.
        self._vbm("controlvm", vm, "poweroff")
        self._vbm("snapshot", vm, "restore", name)

    def delete_snapshot(self, vm: str, name: str) -> None:
        self._vbm("snapshot", vm, "delete", name)

    def start(self, vm: str, headless: bool = True) -> None:
        self._vbm("startvm", vm, "--type", "headless" if headless else "gui")

    def stop(self, vm: str, save: bool = False) -> None:
        self._vbm("controlvm", vm, "savestate" if save else "poweroff")

    def exec(self, vm, argv, *, user, password, timeout, network="off") -> ExecResult:
        args = ["guestcontrol", vm, "run",
                "--username", user, "--password-file", "-",
                "--exe", argv[0], "--", *argv]
        r = self._vbm(*args, stdin=password, timeout=timeout)
        return ExecResult(r.returncode, r.stdout, r.stderr, r.timed_out)

    def copy_in(self, vm, host, guest, *, user, password) -> None:
        winhost = to_windows_path(host)
        self._vbm("guestcontrol", vm, "copyto",
                  "--username", user, "--password-file", "-", winhost, guest,
                  stdin=password)

    def copy_out(self, vm, guest, host, *, user, password) -> None:
        winhost = to_windows_path(host)
        self._vbm("guestcontrol", vm, "copyfrom",
                  "--username", user, "--password-file", "-", guest, winhost,
                  stdin=password)
