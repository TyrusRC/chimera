"""Cryptography misuse vulnerability rules."""

from __future__ import annotations

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext


class CryptoRules(VulnRule):
    def rule_id(self) -> str: return "CRYPTO"
    def title(self) -> str: return "Crypto misuse rules"
    def severity_default(self) -> str: return "high"
    def platforms(self) -> list[str]: return ["android", "ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ecb_mode(context))
        findings.extend(self._check_weak_prng(context))
        findings.extend(self._check_weak_hash(context))
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_ecb_mode(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'AES/ECB|DES/ECB|Cipher\.getInstance\s*\(\s*"[^"]*ECB'):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="CRYPTO-001",
                severity=Severity.HIGH,
                title="AES-ECB mode usage",
                description=f"ECB mode leaks data patterns: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings

    def _check_weak_prng(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'new\s+java\.util\.Random\s*\(|new\s+Random\s*\('):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="CRYPTO-003",
                severity=Severity.MEDIUM,
                title="Weak PRNG (java.util.Random)",
                description=f"java.util.Random is predictable, use SecureRandom: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings

    def _check_weak_hash(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file, line, text in context.search_sources(r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)'):
            rel = file.relative_to(context.jadx_sources_dir) if context.jadx_sources_dir else file
            findings.append(Finding(
                rule_id="CRYPTO-004",
                severity=Severity.HIGH,
                title="Weak hash algorithm (MD5/SHA1)",
                description=f"MD5/SHA1 is cryptographically broken: {rel}:{line}",
                location=f"{rel}:{line}",
                evidence_static=text[:200],
            ))
        return findings
