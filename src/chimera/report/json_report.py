"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from chimera.vuln.finding import Finding


def generate_json(findings: list[Finding], binary_info: dict | None = None) -> str:
    report = {
        "tool": "chimera",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary": binary_info or {},
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(report, indent=2)
