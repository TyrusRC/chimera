"""Markdown report generator."""

from __future__ import annotations

from chimera.vuln.finding import Finding


def generate_markdown(findings: list[Finding], binary_info: dict | None = None) -> str:
    lines = ["# Chimera Security Report", ""]

    if binary_info:
        lines.append(f"**Target:** {binary_info.get('name', 'unknown')}")
        lines.append(f"**SHA256:** {binary_info.get('sha256', 'unknown')[:16]}...")
        lines.append(f"**Platform:** {binary_info.get('platform', 'unknown')}")
        lines.append("")

    # Summary
    total = len(findings)
    crit = sum(1 for f in findings if f.severity.value == "critical")
    high = sum(1 for f in findings if f.severity.value == "high")
    med = sum(1 for f in findings if f.severity.value == "medium")
    low = sum(1 for f in findings if f.severity.value == "low")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Critical | {crit} |")
    lines.append(f"| High | {high} |")
    lines.append(f"| Medium | {med} |")
    lines.append(f"| Low | {low} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    # Findings detail
    lines.append("## Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev_badge = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}.get(f.severity.value, "INFO")
        lines.append(f"### {i}. [{sev_badge}] {f.title}")
        lines.append("")
        lines.append(f"**Rule:** {f.rule_id}")
        if f.masvs_category:
            lines.append(f"**MASVS:** {f.masvs_category}")
        if f.mastg_test:
            lines.append(f"**MASTG:** {f.mastg_test}")
        lines.append(f"**Location:** `{f.location}`")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        if f.evidence_static:
            lines.append("**Evidence:**")
            lines.append(f"```")
            lines.append(f.evidence_static)
            lines.append(f"```")
            lines.append("")
        if f.business_impact:
            lines.append(f"**Business Impact:** {f.business_impact}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
