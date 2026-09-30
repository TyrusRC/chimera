"""Managed-VM capability: provider registry."""
from __future__ import annotations

from chimera.dynamic.vm.base import ExecResult, VmError, VmInfo, VmProvider
from chimera.dynamic.vm.virtualbox import VirtualBoxProvider

PROVIDERS: dict[str, type] = {
    "virtualbox": VirtualBoxProvider,
}


def get_provider(name: str | None = None) -> VmProvider | None:
    if name is not None:
        cls = PROVIDERS.get(name)
        return cls() if cls else None
    for cls in PROVIDERS.values():
        p = cls()
        if p.available():
            return p
    return None


__all__ = ["PROVIDERS", "get_provider", "VmProvider", "VmInfo", "ExecResult",
           "VmError", "VirtualBoxProvider"]
