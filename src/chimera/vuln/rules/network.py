"""Network vulnerability rules."""

from __future__ import annotations

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext


class NetworkRules(VulnRule):
    def rule_id(self) -> str: return "NET"
    def title(self) -> str: return "Network rules"
    def severity_default(self) -> str: return "high"
    def platforms(self) -> list[str]: return ["android", "ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_trust_all(context))
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_trust_all(self, context: ScanContext) -> list[Finding]:
        import re
        findings = []
        # Pattern to match empty or noop checkServerTrusted method body
        empty_body_pattern = re.compile(
            r'checkServerTrusted[^{]*\{[\s]*(?://[^\n]*)?\s*\}', re.DOTALL
        )
        for file, line, text in context.search_sources(r'implements\s+X509TrustManager'):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            try:
                content = file.read_text(errors="replace")
                if "checkServerTrusted" not in content:
                    continue
                # Check if the method body is effectively empty using the regex
                if empty_body_pattern.search(content) or "// trust all" in content.lower():
                    findings.append(Finding(
                        rule_id="NET-003",
                        severity=Severity.HIGH,
                        title="Trust-all TrustManager",
                        description=f"Custom X509TrustManager accepts all certificates: {rel}",
                        location=f"{rel}:{line}",
                        evidence_static="implements X509TrustManager with empty/noop checkServerTrusted",
                        business_impact="MITM attack possible without certificate validation",
                    ))
            except OSError:
                continue
        return findings
