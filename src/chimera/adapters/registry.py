"""Adapter registry — discovers and routes work to available backends."""

from __future__ import annotations

from chimera.adapters.base import BackendAdapter


class AdapterRegistry:
    def __init__(self):
        self._adapters: dict[str, BackendAdapter] = {}

    def register(self, adapter: BackendAdapter) -> None:
        self._adapters[adapter.name()] = adapter

    def get(self, name: str) -> BackendAdapter | None:
        return self._adapters.get(name)

    def find_for_format(self, binary_format: str) -> list[BackendAdapter]:
        return [
            a for a in self._adapters.values()
            if binary_format in a.supported_formats() and a.is_available()
        ]

    def all_available(self) -> list[BackendAdapter]:
        return [a for a in self._adapters.values() if a.is_available()]

    def all_registered(self) -> list[BackendAdapter]:
        return list(self._adapters.values())
