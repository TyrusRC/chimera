"""STIX 2.1 bundle exporter for IoCs.

Each IocMatch becomes a STIX Indicator object whose `pattern` is a
single-property comparison expression. The bundle also includes one
Identity object (the chimera analysis run) and one Malware-Analysis
object that ties everything together.

The output dict is JSON-serializable; analysts ingest it into MISP /
TAXII servers / OpenCTI.
"""
from __future__ import annotations

import datetime
import uuid
from typing import Any

from chimera.detection_engineering.ioc_scanner import IocMatch
from chimera.model.program import UnifiedProgramModel


SPEC_VERSION = "2.1"
TLP_AMBER_DEF_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _pattern_for(match: IocMatch) -> str | None:
    """Return a STIX pattern expression for the match, or None if
    the category isn't supported."""
    v = match.value.replace("'", "\\'")
    cat = match.category
    if cat == "url":
        return f"[url:value = '{v}']"
    if cat == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if cat == "ipv6":
        return f"[ipv6-addr:value = '{v}']"
    if cat == "domain" or cat == "onion_v3":
        return f"[domain-name:value = '{v}']"
    if cat == "email":
        return f"[email-addr:value = '{v}']"
    if cat == "hash_md5":
        return f"[file:hashes.MD5 = '{v}']"
    if cat == "hash_sha1":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if cat == "hash_sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    if cat == "btc_address":
        return f"[x-cryptocurrency-address:value = '{v}']"
    return None


_CONF_TO_NUMERIC = {"high": 90, "medium": 60, "low": 30}


def _build_indicator(match: IocMatch, identity_id: str, ts: str) -> dict[str, Any] | None:
    pattern = _pattern_for(match)
    if pattern is None:
        return None
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _new_id("indicator"),
        "created_by_ref": identity_id,
        "created": ts,
        "modified": ts,
        "name": f"{match.category}: {match.value[:80]}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "confidence": _CONF_TO_NUMERIC.get(match.confidence, 50),
        "labels": [match.category],
    }
    if match.notes:
        indicator["description"] = match.notes
    return indicator


def build_stix_bundle(
    model: UnifiedProgramModel,
    matches: list[IocMatch],
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from the analyzed binary + IoCs."""
    ts = _now()
    identity_id = _new_id("identity")
    identity = {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": identity_id,
        "created": ts,
        "modified": ts,
        "name": "chimera",
        "identity_class": "system",
        "description": "Chimera analysis pipeline",
    }

    sha = model.binary.sha256
    file_observable_id = _new_id("file")
    file_observable = {
        "type": "file",
        "spec_version": SPEC_VERSION,
        "id": file_observable_id,
        "name": model.binary.path.name,
        "hashes": {"SHA-256": sha},
    }

    malware_analysis_id = _new_id("malware-analysis")
    malware_analysis = {
        "type": "malware-analysis",
        "spec_version": SPEC_VERSION,
        "id": malware_analysis_id,
        "created": ts,
        "modified": ts,
        "created_by_ref": identity_id,
        "product": "chimera",
        "version": "0.1.0",
        "analysis_started": ts,
        "analysis_ended": ts,
        "result": "unknown",
        "sample_ref": file_observable_id,
    }

    objects: list[dict[str, Any]] = [identity, file_observable, malware_analysis]
    indicators: list[dict[str, Any]] = []
    for m in matches:
        ind = _build_indicator(m, identity_id, ts)
        if ind is not None:
            indicators.append(ind)
    objects.extend(indicators)

    # Relationships: each indicator → indicates → the malware-analysis
    for ind in indicators:
        objects.append({
            "type": "relationship",
            "spec_version": SPEC_VERSION,
            "id": _new_id("relationship"),
            "created": ts,
            "modified": ts,
            "created_by_ref": identity_id,
            "relationship_type": "indicates",
            "source_ref": ind["id"],
            "target_ref": malware_analysis_id,
        })

    return {
        "type": "bundle",
        "id": _new_id("bundle"),
        "objects": objects,
    }
