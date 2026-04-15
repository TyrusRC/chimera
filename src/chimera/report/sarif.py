"""SARIF 2.1.0 report generator."""

from __future__ import annotations

import json
from chimera.vuln.finding import Finding, Severity

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def generate_sarif(findings: list[Finding], tool_name: str = "chimera",
                   tool_version: str = "0.1.0") -> str:
    rules = {}
    results = []

    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "properties": {},
            }
            if f.masvs_category:
                rules[f.rule_id]["properties"]["masvs"] = f.masvs_category
            if f.mastg_test:
                rules[f.rule_id]["properties"]["mastg"] = f.mastg_test

        result = {
            "ruleId": f.rule_id,
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.split(":")[0]},
                },
            }],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "status": f.status.value,
            },
        }

        # Add line number if present
        if ":" in f.location:
            parts = f.location.rsplit(":", 1)
            if parts[1].isdigit():
                result["locations"][0]["physicalLocation"]["region"] = {
                    "startLine": int(parts[1])
                }

        if f.evidence_static:
            result["properties"]["evidence_static"] = f.evidence_static
        if f.evidence_dynamic:
            result["properties"]["evidence_dynamic"] = f.evidence_dynamic
        if f.business_impact:
            result["properties"]["business_impact"] = f.business_impact

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }

    return json.dumps(sarif, indent=2)
