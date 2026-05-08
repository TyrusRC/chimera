"""Build a MASVS v2 coverage matrix from an analyzed model + cache.

The matrix is engagement-grade output for mobile-app pentests. Each row
is one MASVS category with a status the analyst can refine. We
deliberately default to `analyst_required` for anything that can't be
automatically asserted — Chimera flags candidates, the analyst confirms.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from chimera.model.binary import BinaryFormat
from chimera.model.program import UnifiedProgramModel


_MASVS_CATEGORIES = (
    ("MASVS-STORAGE", "Sensitive data storage"),
    ("MASVS-CRYPTO", "Cryptography"),
    ("MASVS-AUTH", "Authentication and session"),
    ("MASVS-NETWORK", "Network communication / TLS"),
    ("MASVS-PLATFORM", "Platform interaction"),
    ("MASVS-CODE", "Code quality"),
    ("MASVS-RESILIENCE", "Anti-tamper / anti-debug / root detection"),
    ("MASVS-PRIVACY", "Privacy"),
)

# Status taxonomy
STATUS_COVERED = "covered"
STATUS_PARTIAL = "partial"
STATUS_ANALYST = "analyst_required"
STATUS_NA = "not_applicable"


@dataclass
class MasvsRow:
    control_id: str
    name: str
    status: str
    notes: str = ""
    evidence_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "status": self.status,
            "notes": self.notes,
            "evidence_keys": self.evidence_keys,
        }


def _is_mobile(model: UnifiedProgramModel) -> bool:
    return model.binary.format.is_mobile


def _has_crypto_yara_hits(cache_blobs: dict[str, dict]) -> tuple[bool, list[str]]:
    """Look across cached yara_* blobs for crypto-related rule kinds."""
    triggers: list[str] = []
    for key, blob in cache_blobs.items():
        if not key.startswith("yara_"):
            continue
        for hit in (blob.get("yara_hits") or []):
            meta = hit.get("meta") or {}
            kind = meta.get("kind", "")
            if "crypto" in kind:
                triggers.append(hit.get("rule", "?"))
    return bool(triggers), triggers[:5]


def _has_protection_profile_signals(cache, sha: str) -> dict[str, bool]:
    """Pull the bypass/detector ProtectionProfile if cached."""
    blob = cache.get_json(sha, "protection_profile") or {}
    return {
        "ssl_pinning": bool(blob.get("ssl_pinning") or blob.get("ssl_pinning_detected")),
        "root_detection": bool(blob.get("root_detection") or blob.get("root_detected")),
        "anti_debug": bool(blob.get("anti_debug") or blob.get("anti_debug_detected")),
        "anti_frida": bool(blob.get("anti_frida") or blob.get("anti_frida_detected")),
        "tamper_detect": bool(blob.get("tamper_detect") or blob.get("tamper_detected")),
    }


def _has_native_protection_signals(cache, sha: str) -> dict[str, bool]:
    blob = cache.get_json(sha, "native_protection") or {}
    return {
        "anti_debug": bool(blob.get("has_anti_debug")),
        "obfuscation": bool(blob.get("packer") or blob.get("obfuscation")),
    }


def _has_sdk_categories(cache, sha: str) -> set[str]:
    """Return the set of SDK categories detected (from chimera sdks)."""
    blob = cache.get_json(sha, "sdks") or {}
    cats: set[str] = set()
    for sdk in blob.get("matches") or []:
        cat = sdk.get("category") or sdk.get("type")
        if cat:
            cats.add(cat.lower())
    return cats


def build_masvs_matrix(model: UnifiedProgramModel, cache) -> dict[str, Any]:
    """Build a MASVS v2 coverage matrix for the analyzed binary.

    Returns a JSON-shaped dict:
        {
            "applicable": bool,
            "reason": str,
            "rows": [{"control_id": ..., "name": ..., "status": ..., "notes": ..., ...}],
        }
    """
    if not _is_mobile(model):
        return {
            "applicable": False,
            "reason": "non-mobile binary; MASVS not applicable",
            "rows": [],
        }

    sha = model.binary.sha256

    # Collect cache blobs we'll need (keyed by category prefix).
    cache_blobs: dict[str, dict] = {}
    try:
        for k in cache.list_keys(sha):
            if k.startswith(("yara_", "native_protection", "protection_profile", "sdks")):
                blob = cache.get_json(sha, k)
                if isinstance(blob, dict):
                    cache_blobs[k] = blob
    except Exception:
        pass

    crypto_hit, crypto_triggers = _has_crypto_yara_hits(cache_blobs)
    pp = _has_protection_profile_signals(cache, sha)
    native_pp = _has_native_protection_signals(cache, sha)
    sdk_cats = _has_sdk_categories(cache, sha)

    rows: list[MasvsRow] = []

    # STORAGE — always analyst_required (no auto-detection)
    rows.append(MasvsRow(
        control_id="MASVS-STORAGE",
        name="Sensitive data storage",
        status=STATUS_ANALYST,
        notes="Manual review of storage APIs and data classification required.",
    ))

    # CRYPTO
    if crypto_hit:
        rows.append(MasvsRow(
            control_id="MASVS-CRYPTO",
            name="Cryptography",
            status=STATUS_PARTIAL,
            notes=f"YARA crypto hits: {', '.join(crypto_triggers)}",
            evidence_keys=[k for k in cache_blobs if k.startswith("yara_")][:3],
        ))
    else:
        rows.append(MasvsRow(
            control_id="MASVS-CRYPTO",
            name="Cryptography",
            status=STATUS_ANALYST,
            notes="No YARA crypto hits; manual review required.",
        ))

    # AUTH
    rows.append(MasvsRow(
        control_id="MASVS-AUTH",
        name="Authentication and session",
        status=STATUS_ANALYST,
        notes="Manual review of session/credential handling required.",
    ))

    # NETWORK
    if pp.get("ssl_pinning"):
        rows.append(MasvsRow(
            control_id="MASVS-NETWORK",
            name="Network communication / TLS",
            status=STATUS_PARTIAL,
            notes="SSL pinning patterns detected; verify enforcement under runtime tampering.",
            evidence_keys=["protection_profile"],
        ))
    else:
        rows.append(MasvsRow(
            control_id="MASVS-NETWORK",
            name="Network communication / TLS",
            status=STATUS_ANALYST,
            notes="No SSL-pinning patterns auto-detected; manual review required.",
        ))

    # PLATFORM
    rows.append(MasvsRow(
        control_id="MASVS-PLATFORM",
        name="Platform interaction",
        status=STATUS_ANALYST,
        notes="Manual review of IPC, WebView, deeplinks required.",
    ))

    # CODE
    if native_pp.get("obfuscation"):
        rows.append(MasvsRow(
            control_id="MASVS-CODE",
            name="Code quality",
            status=STATUS_PARTIAL,
            notes="Obfuscation/packer detected — manual review of code quality may be limited.",
            evidence_keys=["native_protection"],
        ))
    else:
        rows.append(MasvsRow(
            control_id="MASVS-CODE",
            name="Code quality",
            status=STATUS_ANALYST,
            notes="No obfuscation auto-detected; manual review required.",
        ))

    # RESILIENCE
    has_root = pp.get("root_detection")
    has_anti_debug = pp.get("anti_debug") or native_pp.get("anti_debug")
    has_anti_frida = pp.get("anti_frida")
    resilience_count = sum([bool(has_root), bool(has_anti_debug), bool(has_anti_frida)])
    if resilience_count >= 2:
        rows.append(MasvsRow(
            control_id="MASVS-RESILIENCE",
            name="Anti-tamper / anti-debug / root detection",
            status=STATUS_COVERED,
            notes=f"{resilience_count}/3 resilience signals present (root/anti-debug/anti-Frida).",
            evidence_keys=["protection_profile", "native_protection"],
        ))
    elif resilience_count == 1:
        rows.append(MasvsRow(
            control_id="MASVS-RESILIENCE",
            name="Anti-tamper / anti-debug / root detection",
            status=STATUS_PARTIAL,
            notes="One resilience signal detected; expand coverage.",
            evidence_keys=["protection_profile"],
        ))
    else:
        rows.append(MasvsRow(
            control_id="MASVS-RESILIENCE",
            name="Anti-tamper / anti-debug / root detection",
            status=STATUS_ANALYST,
            notes="No resilience signals auto-detected; binary may lack RASP.",
        ))

    # PRIVACY
    privacy_relevant = sdk_cats & {"analytics", "advertising", "ads", "crash_reporting", "telemetry"}
    if privacy_relevant:
        rows.append(MasvsRow(
            control_id="MASVS-PRIVACY",
            name="Privacy",
            status=STATUS_PARTIAL,
            notes=f"Privacy-relevant SDKs detected: {', '.join(sorted(privacy_relevant))}",
            evidence_keys=["sdks"],
        ))
    else:
        rows.append(MasvsRow(
            control_id="MASVS-PRIVACY",
            name="Privacy",
            status=STATUS_ANALYST,
            notes="No privacy-relevant SDKs auto-detected; manual review required.",
        ))

    return {
        "applicable": True,
        "reason": "",
        "rows": [r.to_dict() for r in rows],
    }
