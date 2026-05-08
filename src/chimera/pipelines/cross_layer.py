"""Cross-layer linker — emit CallEdges connecting JVM methods to native
functions via JNI.

Three edge types:
    - `jni-static`  : `Java_<class>_<method>` symbol match
    - `jni-dynamic` : recovered from RegisterNatives table
    - `calls`       : Java caller of a native method (intra-JVM)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from chimera.model.program import UnifiedProgramModel
from chimera.parsers.jni_mangling import mangle

logger = logging.getLogger(__name__)


@dataclass
class JniLinkResult:
    static_edges: int = 0
    dynamic_edges: int = 0
    callsite_edges: int = 0
    unresolved: int = 0


def _index_native_exports(
    native_exports: dict[str, list[tuple[str, str]]],
) -> dict[str, str]:
    """Flatten {lib: [(symbol, addr), ...]} -> {symbol: addr}.

    On collision, the first lib wins; we log the duplicate.
    """
    out: dict[str, str] = {}
    for lib, items in native_exports.items():
        for sym, addr in items:
            if sym in out and out[sym] != addr:
                logger.debug("duplicate JNI symbol %s in %s; keeping first", sym, lib)
                continue
            out[sym] = addr
    return out


def link_jni_static(
    model: UnifiedProgramModel,
    native_exports: dict[str, list[tuple[str, str]]],
) -> JniLinkResult:
    """For each JVM native method, look up its mangled Java_* symbol in
    the native export index. Emit a `jni-static` CallEdge on match;
    record unresolved otherwise.
    """
    sym_index = _index_native_exports(native_exports)
    result = JniLinkResult()
    for f in model.functions:
        if f.layer != "jvm":
            continue
        if not f.metadata or not f.metadata.get("is_native"):
            continue
        cls = f.metadata.get("class_fqcn", "")
        sig = f.metadata.get("smali_sig", "")
        # Try short form first (non-overloaded), then overloaded form.
        short = mangle(cls, f.name)
        long_ = mangle(cls, f.name, smali_sig=sig, overloaded=True) if sig else None
        target_addr: str | None = None
        if short in sym_index:
            target_addr = sym_index[short]
        elif long_ and long_ in sym_index:
            target_addr = sym_index[long_]
        if target_addr is None:
            result.unresolved += 1
            continue
        model.add_call_edge(f.address, target_addr, "jni-static")
        result.static_edges += 1
    logger.info("jni-static link: %d edges, %d unresolved",
                result.static_edges, result.unresolved)
    return result


def collect_native_exports_from_cache(
    cache, sha256: str, lib_keys: list[str],
) -> dict[str, list[tuple[str, str]]]:
    """Pull `Java_*` exports from cached r2 triage blobs.

    Each lib_key is a cache key like `r2_libnative.so`. Falls back to
    scanning `functions` for `Java_`-prefixed names when no `exports`
    field is present.
    """
    out: dict[str, list[tuple[str, str]]] = {}
    for key in lib_keys:
        blob = cache.get_json(sha256, key) or {}
        lib = key.removeprefix("r2_") or key
        items: list[tuple[str, str]] = []
        for sym in (blob.get("exports") or []):
            name = sym.get("name", "")
            if name.startswith("Java_"):
                items.append((name, hex(sym.get("vaddr", 0))))
        if not items:
            for fn in blob.get("functions") or []:
                name = fn.get("name", "")
                if name.startswith("Java_"):
                    items.append((name, hex(fn.get("vaddr", 0))))
        if items:
            out[lib] = items
    return out


def _index_jvm_native_methods(model: UnifiedProgramModel) -> dict[tuple[str, str], str]:
    """Return {(class_fqcn, method_name): jvm_address} for native methods.

    When multiple overloads exist, prefers the first one. Callsite
    discovery is name-only, so overload resolution is best-effort.
    """
    out: dict[tuple[str, str], str] = {}
    for f in model.functions:
        if f.layer != "jvm":
            continue
        if not f.metadata or not f.metadata.get("is_native"):
            continue
        key = (f.metadata.get("class_fqcn", ""), f.name)
        out.setdefault(key, f.address)
    return out


def link_jvm_callsites(model: UnifiedProgramModel, callsites) -> int:
    """Emit `calls` edges from each callsite's enclosing method to the
    matching native method address. Returns the number of edges added.

    Resolution order:
        1. same-class method match
        2. any class with that method name (best-effort)
    """
    native_index = _index_jvm_native_methods(model)
    by_name: dict[str, list[str]] = {}
    for (cls, name), addr in native_index.items():
        by_name.setdefault(name, []).append(addr)
    edges = 0
    for cs in callsites:
        caller_addr = (
            f"jvm:{cs.caller.class_fqcn}::{cs.caller.name}{cs.caller.smali_sig}"
        )
        if model.get_function(caller_addr) is None:
            continue
        same_class_addr = native_index.get(
            (cs.caller.class_fqcn, cs.callee_name)
        )
        if same_class_addr is not None:
            model.add_call_edge(caller_addr, same_class_addr, "calls")
            edges += 1
            continue
        candidates = by_name.get(cs.callee_name, [])
        if len(candidates) == 1:
            model.add_call_edge(caller_addr, candidates[0], "calls")
            edges += 1
    return edges
