"""SARIF v2.1.0 export for Chimera findings.

Maps the project's CVSS-driven `Finding` model to a SARIF document analysts
or CI pipelines can consume with standard tooling (GitHub code scanning,
Sonar, etc.).
"""
from __future__ import annotations

from typing import Iterable

from chimera.detection_engineering.cvss_findings import Finding


_SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "note",
    "None": "none",
}


def _severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def _evidence_to_location(evidence: str) -> dict:
    """Best-effort SARIF physicalLocation derived from a finding's evidence string.

    Chimera evidence is free-form text (e.g. "AndroidManifest.xml:14 cleartextTraffic=true").
    We parse out a file/region when the colon-separated prefix looks file-like; otherwise
    fall back to a sole snippet field.
    """
    file_part, _, _rest = evidence.partition(":")
    location: dict = {"physicalLocation": {}}
    if file_part and any(file_part.endswith(ext) for ext in (".xml", ".plist", ".so", ".dll", ".dex", ".jar", ".bin", ".apk", ".ipa")):
        location["physicalLocation"]["artifactLocation"] = {"uri": file_part}
    location["physicalLocation"]["region"] = {"snippet": {"text": evidence}}
    return location


def findings_to_sarif(findings: Iterable[Finding], tool_version: str | None = None) -> dict:
    """Convert Chimera findings to a SARIF v2.1.0 document.

    `tool_version` defaults to the installed package version so downstream
    aggregators (CodeQL, GitHub code-scanning, etc.) see a value that
    actually moves when chimera does.
    """
    if tool_version is None:
        try:
            from chimera import __version__ as tool_version
        except Exception:
            tool_version = "0.0.0"
    findings = list(findings)
    rules = [
        {
            "id": f.finding_id,
            "name": f.finding_id,
            "shortDescription": {"text": f.title or f.finding_id},
            "fullDescription": {"text": f.description or f.title or f.finding_id},
            "defaultConfiguration": {"level": _severity_to_level(f.severity)},
            "properties": {
                "cvss_vector": f.cvss_vector,
                "cvss_base_score": f.cvss_base_score,
                "severity": f.severity,
                "masvs_id": f.masvs_id,
                "cwe_id": f.cwe_id,
            },
        }
        for f in findings
    ]
    results = [
        {
            "ruleId": f.finding_id,
            "level": _severity_to_level(f.severity),
            "message": {"text": f.description or f.title or ""},
            "locations": [_evidence_to_location(e) for e in (f.evidence or [""])[:5]],
        }
        for f in findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "chimera",
                        "version": tool_version,
                        "informationUri": "https://github.com/chimera",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
