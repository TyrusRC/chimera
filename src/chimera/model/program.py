"""Unified Program Model — shared state fed by all backends."""

from __future__ import annotations

import re as _re

from chimera.model.binary import BinaryInfo
from chimera.model.function import FunctionInfo, StringEntry, CallEdge
from chimera.model.objc import ObjCCallSite, ObjCCategory, ObjCClass, ObjCMethod, ObjCProtocol


class UnifiedProgramModel:
    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        self._functions: dict[str, FunctionInfo] = {}
        self._call_edges: list[CallEdge] = []
        self._strings: list[StringEntry] = []
        self._objc_methods: list[ObjCMethod] = []
        self._objc_callsites: list[ObjCCallSite] = []
        self._objc_classes: dict[str, ObjCClass] = {}
        self._objc_categories: dict[str, ObjCCategory] = {}
        self._objc_protocols: dict[str, ObjCProtocol] = {}
        self._regex_cache: dict[str, _re.Pattern[str]] = {}

    @property
    def functions(self) -> list[FunctionInfo]:
        return list(self._functions.values())

    def add_function(self, func: FunctionInfo) -> None:
        existing = self._functions.get(func.address)
        if existing is None:
            # Seed sources from the first backend
            if not func.sources:
                func.sources = [func.source_backend]
            self._functions[func.address] = func
            return
        # Merge: keep first-seen function, record additional backend
        if func.source_backend and func.source_backend not in existing.sources:
            existing.sources.append(func.source_backend)

    def get_function(self, address: str) -> FunctionInfo | None:
        return self._functions.get(address)

    def get_functions_by_classification(self, classification: str) -> list[FunctionInfo]:
        return [f for f in self._functions.values() if f.classification == classification]

    def get_functions_by_layer(self, layer: str) -> list[FunctionInfo]:
        return [f for f in self._functions.values() if f.layer == layer]

    def add_call_edge(self, caller_addr: str, callee_addr: str, call_type: str = "direct") -> None:
        """Record a call edge. Addresses need not exist yet - unresolved edges are
        silently dropped by `get_callees`/`get_callers` at query time."""
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
        regex = self._regex_cache.get(pattern)
        if regex is None:
            regex = _re.compile(pattern, _re.IGNORECASE)
            self._regex_cache[pattern] = regex
        return [s for s in self._strings if regex.search(s.value)]

    @property
    def objc_methods(self) -> list[ObjCMethod]:
        return list(self._objc_methods)

    @property
    def objc_callsites(self) -> list[ObjCCallSite]:
        return list(self._objc_callsites)

    @property
    def objc_classes(self) -> list[ObjCClass]:
        return list(self._objc_classes.values())

    @property
    def objc_categories(self) -> list[ObjCCategory]:
        return list(self._objc_categories.values())

    @property
    def objc_protocols(self) -> list[ObjCProtocol]:
        return list(self._objc_protocols.values())

    def add_objc_method(self, m: ObjCMethod) -> None:
        self._objc_methods.append(m)

    def add_objc_callsite(self, cs: ObjCCallSite) -> None:
        self._objc_callsites.append(cs)

    def add_objc_class(self, c: ObjCClass) -> None:
        self._objc_classes[c.name] = c

    def add_objc_category(self, c: ObjCCategory) -> None:
        self._objc_categories[c.name] = c

    def add_objc_protocol(self, p: ObjCProtocol) -> None:
        self._objc_protocols[p.name] = p

    def rename_objc_class(self, old_name: str, new_name: str) -> None:
        """Atomically rename an ObjCClass and propagate to all ObjCMethods.

        Updates self._objc_classes dict key, the class's .name field, and
        every ObjCMethod.class_name that referenced the old name.
        Idempotent if old == new or old not present.
        """
        if old_name == new_name:
            return
        cls = self._objc_classes.pop(old_name, None)
        if cls is None:
            return
        cls.name = new_name
        self._objc_classes[new_name] = cls
        for m in self._objc_methods:
            if m.class_name == old_name:
                m.class_name = new_name

    def find_objc_method(
        self,
        *,
        selector: str,
        class_name: str | None = None,
    ) -> list[ObjCMethod]:
        out = []
        for m in self._objc_methods:
            if m.selector != selector:
                continue
            if class_name is not None and m.class_name != class_name:
                continue
            out.append(m)
        return out

    def find_objc_callers(self, imp_address: str) -> list[ObjCCallSite]:
        # Resolve the IMP address back to a class+selector first.
        method = next(
            (m for m in self._objc_methods if m.imp_address == imp_address),
            None,
        )
        if method is None:
            return []
        out = []
        for cs in self._objc_callsites:
            if cs.selector != method.selector:
                continue
            if cs.receiver_class is None:
                # Dynamic dispatch — counts as a possible caller.
                out.append(cs)
                continue
            if cs.receiver_class == method.class_name:
                out.append(cs)
        return out
