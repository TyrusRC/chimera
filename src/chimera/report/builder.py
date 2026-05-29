"""Build a single self-contained report from an analyzed model + cache.

Produces a `dict` payload that callers can serialize to JSON, and a
`render_html` helper that turns the same payload into a one-file HTML
view an analyst can open in a browser. The payload is the source of
truth — HTML is a presentation layer over it.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chimera.core.cache import AnalysisCache
from chimera.detection_engineering.masvs import build_masvs_matrix
from chimera.model.program import UnifiedProgramModel


def _behavior_section(sha: str, cache, native_protection: dict, protection_profile: dict) -> dict:
    """Aggregate anti-analysis / network / persistence / IOC / packer signals."""
    aa_evidence: list[str] = []
    for k in ("anti_debug_evidence", "anti_vm_evidence", "self_inject_evidence"):
        v = (native_protection or {}).get(k) or []
        if isinstance(v, list):
            aa_evidence.extend(str(x) for x in v)

    anti_analysis = {
        "anti_debug": bool((native_protection or {}).get("has_anti_debug")) or bool((protection_profile or {}).get("anti_debug")),
        "anti_vm": bool((native_protection or {}).get("has_anti_vm")) or bool((protection_profile or {}).get("anti_emulator")),
        "anti_frida": bool((protection_profile or {}).get("anti_frida")),
        "root_jailbreak_detect": bool((protection_profile or {}).get("root_detect")) or bool((protection_profile or {}).get("jailbreak_detect")),
        "self_inject": bool((native_protection or {}).get("has_self_inject")),
        "evidence": aa_evidence[:50],
    }

    persistence_raw = cache.get_json(sha, "elf_persistence") or []
    if isinstance(persistence_raw, dict):
        persistence_hits = persistence_raw.get("hits") or []
    else:
        persistence_hits = persistence_raw if isinstance(persistence_raw, list) else []
    persistence = {
        "indicators_present": bool((native_protection or {}).get("has_persistence_strings")) or bool(persistence_hits),
        "elf_persistence_count": len(persistence_hits),
    }

    network = {
        "cleartext_permitted": bool((protection_profile or {}).get("cleartext_traffic")),
        "user_ca_trusted": bool((protection_profile or {}).get("user_ca_trusted")),
        "pinning_present": bool((protection_profile or {}).get("pinning_present")),
    }

    iocs = cache.get_json(sha, "iocs") or {}
    packer = {
        "detected": bool((native_protection or {}).get("packer_detected")),
        "name": (native_protection or {}).get("packer_name"),
    }

    return {
        "anti_analysis": anti_analysis,
        "network": network,
        "persistence": persistence,
        "iocs": iocs,
        "packer": packer,
    }


def _attack_surface_section(model: UnifiedProgramModel, sha: str, cache) -> dict:
    """Format-appropriate entry points an attacker could reach."""
    out: dict = {"format": model.binary.format.value}

    if model.imports:
        by_bucket: dict[str, list[str]] = {}
        for imp in model.imports:
            key = f"{imp.dll}!{imp.name}" if imp.dll else (imp.name or "?")
            by_bucket.setdefault(imp.bucket or "other", []).append(key)
        out["imports_by_bucket"] = {k: sorted(set(v))[:200] for k, v in by_bucket.items()}

    components = cache.get_json(sha, "manifest_components") or []
    if components:
        out["exported_components"] = [
            {"kind": c.get("kind"), "name": c.get("name"), "has_intent_filter": c.get("has_intent_filter", False)}
            for c in components
            if c.get("exported")
        ]

    url_schemes = cache.get_json(sha, "url_schemes") or []
    if url_schemes:
        out["url_schemes"] = list(url_schemes)[:100]

    return out


def _build_objc_section(model: UnifiedProgramModel) -> dict:
    """Surface Objective-C runtime data the iOS/MachO pipelines populate.

    Without this, `objc_methods` / categories / protocols / callsites are
    collected into the model but never reach the JSON/HTML report — the
    analyst can't see the class hierarchy of a native iOS binary.
    """
    methods = model.objc_methods
    callsites = model.objc_callsites
    categories = model.objc_categories
    protocols = model.objc_protocols
    if not (methods or callsites or categories or protocols):
        return {}

    classes: dict[str, dict[str, int]] = {}
    for m in methods:
        c = classes.setdefault(
            m.class_name, {"instance_methods": 0, "class_methods": 0},
        )
        c["class_methods" if m.is_class_method else "instance_methods"] += 1

    return {
        "method_count": len(methods),
        "callsite_count": len(callsites),
        "category_count": len(categories),
        "protocol_count": len(protocols),
        "classes": [
            {"name": name, **counts}
            for name, counts in sorted(classes.items())
        ][:200],
        "categories": [
            {
                "name": c.name,
                "target_class": c.target_class,
                "instance_method_count": len(c.instance_methods),
                "class_method_count": len(c.class_methods),
            }
            for c in categories[:100]
        ],
        "protocols": [
            {
                "name": p.name,
                "required_method_count": len(p.required_methods),
                "optional_method_count": len(p.optional_methods),
            }
            for p in protocols[:100]
        ],
        "callsites_sample": [
            {
                "caller": cs.caller_function,
                "address": cs.call_address,
                "selector": cs.selector,
                "receiver_class": cs.receiver_class,
                "resolution": cs.resolution,
            }
            for cs in callsites[:100]
        ],
    }


def build_report(model: UnifiedProgramModel, cache: AnalysisCache) -> dict:
    """Aggregate model + cache state into one analyst-ready report payload."""
    sha = model.binary.sha256
    triage = cache.get_json(sha, "triage") or {}
    jadx_meta = cache.get_json(sha, "jadx") or {}
    manifest_bytes = cache.get(sha, "manifest_xml")
    native_protections = cache.get_json(sha, "native_protections") or {}
    native_protection = cache.get_json(sha, "native_protection") or {}
    protection_profile = cache.get_json(sha, "protection_profile") or {}

    # Per-native-lib backend results — walk the cache dir.
    sha_dir = cache.cache_dir / sha[:2] / sha
    libs: dict[str, dict[str, Any]] = {}
    if sha_dir.exists():
        for entry in sorted(sha_dir.iterdir()):
            for prefix in ("r2_", "ghidra_"):
                if entry.name.startswith(prefix):
                    lib = entry.name[len(prefix):]
                    tag = prefix.rstrip("_")
                    try:
                        blob = json.loads(entry.read_text())
                    except (OSError, json.JSONDecodeError):
                        continue
                    libs.setdefault(lib, {})[tag] = _summarize_lib_blob(tag, blob)

    cross_layer_bindings: list[dict] = []
    for f in model.functions:
        if f.layer != "jvm":
            continue
        if not f.metadata or not f.metadata.get("is_native"):
            continue
        callees = model.get_callees(f.address)
        if callees:
            for c in callees:
                edge_type = "jni-static"
                for e in model._call_edges:
                    if e.caller_addr == f.address and e.callee_addr == c.address:
                        edge_type = e.call_type
                        break
                cross_layer_bindings.append({
                    "jvm": f.address, "native": c.address, "type": edge_type,
                })
        else:
            cross_layer_bindings.append({
                "jvm": f.address, "native": None, "type": "unbound",
            })

    # Collect ilspy_ keys for .NET assemblies. Read each key once.
    ilspy_payloads = [
        p
        for k in cache.list_keys(sha)
        if k.startswith("ilspy_")
        for p in (cache.get_json(sha, k),)
        if p
    ]

    return {
        "schema": "chimera-report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "binary": {
            "sha256": sha,
            "path": str(model.binary.path),
            "format": model.binary.format.value,
            "platform": model.binary.platform.value,
            "arch": model.binary.arch.value,
            "framework": model.binary.framework.value,
            "size_bytes": model.binary.size_bytes,
            "package_name": model.binary.package_name,
            "version": model.binary.version,
        },
        "triage": triage,
        "jadx": {
            "decompiled_files": jadx_meta.get("decompiled_files", 0),
            "package_count": len(jadx_meta.get("packages", []) or []),
            "packages": jadx_meta.get("packages", []),
            "sources_dir": jadx_meta.get("sources_dir"),
        },
        "native_libraries": libs,
        "model": {
            "function_count": len(model.functions),
            "string_count": len(model.get_strings()),
            "functions": [
                {
                    "address": f.address,
                    "name": f.name,
                    "original_name": f.original_name,
                    "language": f.language,
                    "layer": f.layer,
                    "classification": f.classification,
                    "source_backend": f.source_backend,
                }
                for f in list(model.functions)[:1000]
            ],
            "strings": [
                {"address": s.address, "value": s.value, "section": s.section}
                for s in list(model.get_strings())[:1000]
            ],
            "function_truncated": len(model.functions) > 1000,
            "string_truncated": len(model.get_strings()) > 1000,
        },
        "manifest_present": manifest_bytes is not None,
        "native_protections": native_protections,
        "cross_layer": {"bindings": cross_layer_bindings},
        "pe_header": cache.get_json(sha, "pe_header") or {},
        "pe_imports": cache.get_json(sha, "pe_imports") or {},
        "pe_flags": cache.get_json(sha, "pe_flags") or {},
        "elf_persistence": cache.get_json(sha, "elf_persistence") or [],
        "elf_syscalls": cache.get_json(sha, "elf_syscalls") or {},
        "dotnet_assemblies": ilspy_payloads,
        "native_protection": native_protection,
        "behavior": _behavior_section(sha, cache, native_protection, protection_profile),
        "attack_surface": _attack_surface_section(model, sha, cache),
        "masvs": build_masvs_matrix(model, cache),
        "imports": [
            {"dll": e.dll, "name": e.name, "address": e.address, "ordinal": e.ordinal, "bucket": e.bucket}
            for e in model.imports
        ][:500],
        "objc": _build_objc_section(model),
        "vol_pslist":            cache.get_json(sha, "vol_pslist") or {},
        "vol_pstree":            cache.get_json(sha, "vol_pstree") or {},
        "vol_bash":              cache.get_json(sha, "vol_bash") or {},
        "vol_netstat":           cache.get_json(sha, "vol_netstat") or {},
        "vol_malfind":           cache.get_json(sha, "vol_malfind") or {},
        "vol_lsmod":             cache.get_json(sha, "vol_lsmod") or {},
        "vol_check_modules":     cache.get_json(sha, "vol_check_modules") or {},
        "vol_check_syscall":     cache.get_json(sha, "vol_check_syscall") or {},
        "memory_persistence":    cache.get_json(sha, "memory_persistence") or {},
        "memory_protection":     cache.get_json(sha, "memory_protection") or {},
    }


def _summarize_lib_blob(tag: str, blob: dict) -> dict:
    if tag == "r2":
        return {
            "function_count": len(blob.get("functions") or []),
            "string_count": len(blob.get("strings") or []),
            "arch": (blob.get("info") or {}).get("arch"),
            "bits": (blob.get("info") or {}).get("bits"),
            "stripped": (blob.get("info") or {}).get("stripped"),
        }
    if tag == "ghidra":
        rc = blob.get("return_code")
        return {
            "return_code": rc,
            "ok": rc == 0,
            "error_first_line": (blob.get("error") or "").splitlines()[0:1] or None,
        }
    return {}


# Backwards-compat re-export. Tests still import `render_html` from
# `chimera.report.builder` directly; pin it here so the public surface
# of builder.py stays stable across the data/presentation split.
from chimera.report.html import render_html  # noqa: E402, F401

