"""Unified Program Model — shared state fed by all backends."""

from __future__ import annotations

import re as _re

from chimera.model.binary import BinaryInfo
from chimera.model.function import FunctionInfo, StringEntry, CallEdge


class UnifiedProgramModel:
    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        self._functions: dict[str, FunctionInfo] = {}
        self._call_edges: list[CallEdge] = []
        self._strings: list[StringEntry] = []

    @property
    def functions(self) -> list[FunctionInfo]:
        return list(self._functions.values())

    def add_function(self, func: FunctionInfo) -> None:
        self._functions[func.address] = func

    def get_function(self, address: str) -> FunctionInfo | None:
        return self._functions.get(address)

    def get_functions_by_classification(self, classification: str) -> list[FunctionInfo]:
        return [f for f in self._functions.values() if f.classification == classification]

    def get_functions_by_layer(self, layer: str) -> list[FunctionInfo]:
        return [f for f in self._functions.values() if f.layer == layer]

    def add_call_edge(self, caller_addr: str, callee_addr: str, call_type: str = "direct") -> None:
        self._call_edges.append(CallEdge(caller_addr, callee_addr, call_type))

    def get_callees(self, address: str) -> list[FunctionInfo]:
        callee_addrs = [e.callee_addr for e in self._call_edges if e.caller_addr == address]
        return [self._functions[a] for a in callee_addrs if a in self._functions]

    def get_callers(self, address: str) -> list[FunctionInfo]:
        caller_addrs = [e.caller_addr for e in self._call_edges if e.callee_addr == address]
        return [self._functions[a] for a in caller_addrs if a in self._functions]

    def add_string(self, address: str, value: str, section: str | None = None,
                   decrypted_from: str | None = None) -> None:
        self._strings.append(StringEntry(address=address, value=value,
                                         section=section, decrypted_from=decrypted_from))

    def get_strings(self, pattern: str | None = None) -> list[StringEntry]:
        if pattern is None:
            return list(self._strings)
        regex = _re.compile(pattern, _re.IGNORECASE)
        return [s for s in self._strings if regex.search(s.value)]
