"""Phase 4.5: ObjC cross-references.

Composes the Mach-O ObjC parser, class-dump JSON enricher, and r2 callsite
linker into a single orchestrator. Updates the UnifiedProgramModel and
returns a triage-cache context dict.
"""
from __future__ import annotations

import logging
from pathlib import Path

from chimera.model.objc import ObjCMethod
from chimera.model.program import UnifiedProgramModel
from chimera.parsers.macho_objc import (
    ObjCParseError,
    link_callsites,
    parse_objc_metadata,
)

logger = logging.getLogger(__name__)


def _is_macho(path: Path) -> bool:
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return False
    # 64-bit little-endian Mach-O magic.
    return magic == b"\xcf\xfa\xed\xfe" or magic == b"\xce\xfa\xed\xfe"


def _enrich_from_class_dump(
    model: UnifiedProgramModel,
    cd_json: dict,
) -> int:
    """Apply class-dump human_signature to matching ObjCMethod entries."""
    if not isinstance(cd_json, dict):
        return 0
    enriched = 0
    by_class: dict[str, dict[str, str]] = {}
    for cls in cd_json.get("classes", []):
        cname = cls.get("name")
        if not cname:
            continue
        sig_map: dict[str, str] = {}
        for m in cls.get("instance_methods", []) + cls.get("class_methods", []):
            sel = m.get("selector")
            sig = m.get("human_signature")
            if sel and sig:
                sig_map[sel] = sig
        by_class[cname] = sig_map

    for method in model.objc_methods:
        sig = by_class.get(method.class_name, {}).get(method.selector)
        if sig:
            method.enriched_signature = sig
            enriched += 1
    return enriched


async def build_objc_xref(
    *,
    model: UnifiedProgramModel,
    main_binary: Path,
    class_dump_json: dict | None,
    r2_xrefs: list[dict],
) -> dict:
    """Run Phase 4.5: parse ObjC metadata, enrich, link callsites.

    Returns the triage-cache context dict.
    """
    ctx = {
        "available": False,
        "class_count": 0,
        "method_count": 0,
        "category_count": 0,
        "protocol_count": 0,
        "callsite_count": 0,
        "callsites_resolved_static": 0,
        "callsites_unresolved_dynamic": 0,
        "class_dump_enriched": False,
        "chained_fixups_detected": False,
        "skipped_reason": None,
    }
    if not _is_macho(main_binary):
        ctx["skipped_reason"] = "not_macho"
        return ctx

    try:
        md = parse_objc_metadata(main_binary)
    except ObjCParseError as e:
        logger.warning("ObjC parser failed on %s: %s", main_binary, e)
        ctx["skipped_reason"] = "parser_error"
        return ctx

    ctx["available"] = True
    ctx["chained_fixups_detected"] = md.chained_fixups_detected

    for cls in md.classes:
        model.add_objc_class(cls)
        for m in cls.instance_methods + cls.class_methods:
            model.add_objc_method(m)
    for cat in md.categories:
        for m in cat.instance_methods + cat.class_methods:
            model.add_objc_method(m)
    for proto in md.protocols:
        model.add_objc_protocol(proto)

    ctx["class_count"] = len(md.classes)
    ctx["method_count"] = len(model.objc_methods)
    ctx["category_count"] = len(md.categories)
    ctx["protocol_count"] = len(md.protocols)

    if class_dump_json:
        enriched = _enrich_from_class_dump(model, class_dump_json)
        ctx["class_dump_enriched"] = enriched > 0

    callsites = link_callsites(model.objc_methods, r2_xrefs)
    for cs in callsites:
        model.add_objc_callsite(cs)
    ctx["callsite_count"] = len(callsites)
    ctx["callsites_resolved_static"] = sum(1 for c in callsites if c.resolution == "static")
    ctx["callsites_unresolved_dynamic"] = sum(1 for c in callsites if c.resolution == "dynamic")

    return ctx
