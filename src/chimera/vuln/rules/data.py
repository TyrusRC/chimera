"""Data exposure vulnerability rules."""

from __future__ import annotations

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext


class DataRules(VulnRule):
    def rule_id(self) -> str: return "DATA"
    def title(self) -> str: return "Data exposure rules"
    def severity_default(self) -> str: return "medium"
    def platforms(self) -> list[str]: return ["android", "ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sensitive_logging(context))
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_sensitive_logging(self, context: ScanContext) -> list[Finding]:
        findings = []
        pattern = r'Log\.[dviwef]\s*\([^)]*(?:token|password|secret|credential|auth|session|jwt|bearer)[^)]*\)'
        for file, line, text in context.search_sources(pattern):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="DATA-004",
                severity=Severity.MEDIUM,
                title="Logging sensitive data",
                description=f"Sensitive data may be logged: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings
