"""Types + provider contract for the managed-VM capability."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class VmInfo:
    name: str
    state: str


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class VmError(Exception):
    pass


class VmProvider(Protocol):
    name: str

    def available(self) -> bool: ...
    def list(self) -> list[VmInfo]: ...
    def snapshot(self, vm: str, name: str) -> None: ...
    def revert(self, vm: str, name: str) -> None: ...
    def delete_snapshot(self, vm: str, name: str) -> None: ...
    def start(self, vm: str, headless: bool = True) -> None: ...
    def stop(self, vm: str, save: bool = False) -> None: ...
    def exec(self, vm: str, argv: list[str], *, user: str, password: str,
             timeout: int, network: str = "off") -> ExecResult: ...
    def copy_in(self, vm: str, host: str, guest: str, *, user: str, password: str) -> None: ...
    def copy_out(self, vm: str, guest: str, host: str, *, user: str, password: str) -> None: ...
