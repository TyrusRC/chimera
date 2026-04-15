"""WebView vulnerability rules."""

from __future__ import annotations

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext


class WebViewRules(VulnRule):
    def rule_id(self) -> str: return "WEB"
    def title(self) -> str: return "WebView rules"
    def severity_default(self) -> str: return "high"
    def platforms(self) -> list[str]: return ["android", "ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_js_interface(context))
        findings.extend(self._check_file_access(context))
        findings.extend(self._check_mixed_content(context))
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_js_interface(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'addJavascriptInterface\s*\('):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="WEB-001",
                severity=Severity.HIGH,
                title="JavaScript interface exposed in WebView",
                description=f"addJavascriptInterface exposes native methods to JS: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
                business_impact="Remote code execution if WebView loads attacker-controlled content",
            ))
        return findings

    def _check_file_access(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'setAllowFileAccess\s*\(\s*true\s*\)'):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="WEB-003",
                severity=Severity.MEDIUM,
                title="WebView file access enabled",
                description=f"File access enabled in WebView: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings

    def _check_mixed_content(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'MIXED_CONTENT_ALWAYS_ALLOW'):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="WEB-004",
                severity=Severity.MEDIUM,
                title="Mixed content allowed in WebView",
                description=f"WebView allows loading HTTP content in HTTPS pages: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings
