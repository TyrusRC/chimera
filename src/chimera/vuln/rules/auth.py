"""Authentication & session vulnerability rules."""

from __future__ import annotations

import re

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext

# Patterns that indicate real auth secrets (not map keys, analytics, etc.)
_SECRET_PATTERNS = [
    (r'(?:JWT_SECRET|jwt[_-]?secret|signing[_-]?key)\s*=\s*["\']([^"\']{8,})["\']', "JWT secret"),
    (r'(?:API_KEY|api[_-]?key)\s*=\s*["\'](sk-live-[^"\']+)["\']', "Live API key"),
    (r'(?:API_KEY|api[_-]?key)\s*=\s*["\'](sk-[^"\']{16,})["\']', "Secret API key"),
    (r'(?:SECRET|secret|password|passwd)\s*=\s*["\']([^"\']{8,})["\']', "Hardcoded secret"),
    (r'Bearer\s+([A-Za-z0-9\-_.]{20,})', "Hardcoded bearer token"),
]

# Exclude patterns (not real secrets)
_EXCLUDE_PATTERNS = [
    r'AIzaSy',       # Google Maps / Firebase key (not auth)
    r'AAAA[A-Za-z]', # Firebase messaging key
    r'example\.com',
    r'placeholder',
    r'TODO',
    r'CHANGEME',
]


class AuthRules(VulnRule):
    def rule_id(self) -> str: return "AUTH"
    def title(self) -> str: return "Authentication rules"
    def severity_default(self) -> str: return "critical"
    def platforms(self) -> list[str]: return ["android", "ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_hardcoded_secrets(context))
        findings.extend(self._check_token_in_prefs(context))
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_hardcoded_secrets(self, context: ScanContext) -> list[Finding]:
        findings = []
        for pattern, desc in _SECRET_PATTERNS:
            for file, line, text in context.search_sources(pattern):
                if any(re.search(exc, text) for exc in _EXCLUDE_PATTERNS):
                    continue
                rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
                findings.append(Finding(
                    rule_id="AUTH-001",
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded {desc}",
                    description=f"Found {desc} in source code: {rel}:{line}",
                    location=f"{rel}:{line}",
                    evidence_static=text[:200],
                    business_impact="API key extraction → unauthorized backend access",
                ))
        return findings

    def _check_token_in_prefs(self, context: ScanContext) -> list[Finding]:
        findings = []
        pattern = r'putString\s*\(\s*["\'](?:auth|token|session|access_token|refresh_token|jwt)["\']'
        for file, line, text in context.search_sources(pattern):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="AUTH-003",
                severity=Severity.HIGH,
                title="Auth token stored in SharedPreferences",
                description=f"Sensitive token stored in plaintext SharedPreferences: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
                business_impact="Token extraction from unencrypted SharedPreferences",
            ))
        return findings
