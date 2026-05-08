"""Parse Volatility 3 kernel-side plugin output.

Plugins covered:
  * `linux.lsmod.Lsmod` — loaded kernel modules.
  * `linux.check_modules.Check_modules` — modules in the in-memory list
    that have been hidden from `/proc/modules`.
  * `linux.check_syscall.Check_syscall` — syscall table entries that
    don't resolve to known kernel symbols (rootkit hooks).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class KernelModule:
    name: str
    address: str
    size: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "address": self.address, "size": self.size}


@dataclass
class ModuleAnomaly:
    name: str
    address: str
    note: str  # e.g. "in module list but missing from /proc/modules"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "address": self.address, "note": self.note}


@dataclass
class SyscallHook:
    index: int
    name: str               # syscall name, e.g. "sys_open"
    handler_addr: str       # hex address
    handler_symbol: Optional[str]  # resolved symbol name; None means unknown / hooked

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index, "name": self.name,
            "handler_addr": self.handler_addr,
            "handler_symbol": self.handler_symbol,
        }


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_lsmod(rows: list[dict]) -> list[KernelModule]:
    out: list[KernelModule] = []
    for row in rows or []:
        name = row.get("Name") or row.get("Module") or ""
        if not name:
            continue
        out.append(KernelModule(
            name=str(name),
            address=str(row.get("Offset") or row.get("Address") or ""),
            size=_to_int(row.get("Size")),
        ))
    return out


def parse_check_modules(rows: list[dict]) -> list[ModuleAnomaly]:
    """Vol3's check_modules emits modules that exist in one list but not
    another. Each row carries the name + offset; we record them all as
    anomalies."""
    out: list[ModuleAnomaly] = []
    for row in rows or []:
        name = row.get("Name") or row.get("Module") or row.get("Hidden Module") or ""
        if not name:
            continue
        addr = str(row.get("Offset") or row.get("Address") or "")
        note = str(row.get("Notes") or row.get("Reason")
                   or "module missing from /proc/modules but present in module list")
        out.append(ModuleAnomaly(name=str(name), address=addr, note=note))
    return out


def parse_check_syscall(rows: list[dict]) -> list[SyscallHook]:
    """Vol3's check_syscall emits one row per syscall slot; each row has
    an index, a name (when the table-entry resolves to a known sym), and
    the handler address."""
    out: list[SyscallHook] = []
    for row in rows or []:
        raw_idx = row.get("Index") if row.get("Index") is not None else row.get("Number")
        idx = _to_int(raw_idx)
        if idx is None:
            continue
        name = row.get("Name") or row.get("Syscall") or ""
        handler_addr = str(row.get("Handler") or row.get("Address") or "")
        handler_symbol = row.get("Symbol") or row.get("Module")
        # Vol3 shows "UNKNOWN" or empty when the address doesn't resolve
        if handler_symbol in (None, "", "UNKNOWN", "-"):
            handler_symbol = None
        out.append(SyscallHook(
            index=idx, name=str(name),
            handler_addr=handler_addr,
            handler_symbol=str(handler_symbol) if handler_symbol else None,
        ))
    return out


def filter_hooked_syscalls(hooks: list[SyscallHook]) -> list[SyscallHook]:
    """Filter to only syscalls whose handler doesn't resolve — strong
    rootkit indicator."""
    return [h for h in hooks if h.handler_symbol is None]
