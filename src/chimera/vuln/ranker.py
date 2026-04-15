"""Business impact ranking — sort and deduplicate findings."""

from __future__ import annotations

from chimera.vuln.finding import Finding


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort by severity (critical first), deduplicate by rule_id + location."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f"{f.rule_id}:{f.location}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: f.severity.weight, reverse=True)
    return unique
