"""iOS Info.plist, entitlements, and ATS vulnerability rules."""

from __future__ import annotations

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext


class IosPlistRules(VulnRule):
    def rule_id(self) -> str: return "IOS-PLIST"
    def title(self) -> str: return "iOS Plist/Entitlements rules"
    def severity_default(self) -> str: return "medium"
    def platforms(self) -> list[str]: return ["ios"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        if context.platform != "ios":
            return []

        plist = getattr(context, "ios_plist", None) or {}
        entitlements = getattr(context, "ios_entitlements", None) or {}

        findings: list[Finding] = []
        findings.extend(self._check_ats(plist))
        findings.extend(self._check_url_schemes(plist))
        findings.extend(self._check_entitlements(entitlements))

        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]
        return findings

    def _check_ats(self, plist: dict) -> list[Finding]:
        findings = []
        ats = plist.get("NSAppTransportSecurity", {})

        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append(Finding(
                rule_id="NET-002",
                severity=Severity.HIGH,
                title="App Transport Security disabled (NSAllowsArbitraryLoads)",
                description=(
                    "NSAllowsArbitraryLoads is true — the app can make cleartext HTTP "
                    "connections to any domain. This disables iOS's built-in TLS enforcement."
                ),
                location="Info.plist: NSAppTransportSecurity",
                evidence_static="NSAllowsArbitraryLoads = true",
                business_impact="All network traffic vulnerable to MITM without TLS",
            ))

        exceptions = ats.get("NSExceptionDomains", {})
        for domain, config in exceptions.items():
            if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                findings.append(Finding(
                    rule_id="NET-002",
                    severity=Severity.MEDIUM,
                    title=f"ATS exception: cleartext allowed for {domain}",
                    description=(
                        f"NSExceptionAllowsInsecureHTTPLoads is true for '{domain}'. "
                        f"HTTP traffic to this domain is not encrypted."
                    ),
                    location=f"Info.plist: NSExceptionDomains.{domain}",
                    evidence_static=f"NSExceptionAllowsInsecureHTTPLoads = true for {domain}",
                ))

        return findings

    def _check_url_schemes(self, plist: dict) -> list[Finding]:
        findings = []
        url_types = plist.get("CFBundleURLTypes", [])
        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            for scheme in schemes:
                if scheme.lower() not in ("http", "https", "mailto", "tel", "sms"):
                    findings.append(Finding(
                        rule_id="URL-001",
                        severity=Severity.MEDIUM,
                        title=f"Custom URL scheme: {scheme}://",
                        description=(
                            f"The app registers custom URL scheme '{scheme}://'. "
                            f"Custom schemes can be hijacked by other apps. If the handler "
                            f"doesn't validate input, it may be vulnerable to injection."
                        ),
                        location=f"Info.plist: CFBundleURLSchemes",
                        evidence_static=f"scheme = {scheme}",
                    ))
        return findings

    def _check_entitlements(self, entitlements: dict) -> list[Finding]:
        findings = []

        if entitlements.get("get-task-allow") is True:
            findings.append(Finding(
                rule_id="DATA-003",
                severity=Severity.HIGH,
                title="Debuggable: get-task-allow enabled",
                description=(
                    "The get-task-allow entitlement is true. This allows attaching "
                    "a debugger to the app. Should be false in production builds."
                ),
                location="Entitlements: get-task-allow",
                evidence_static="get-task-allow = true",
                business_impact="Debugger attachment in production → memory inspection",
            ))

        for key in entitlements:
            if key.startswith("com.apple.private."):
                findings.append(Finding(
                    rule_id="IPC-001",
                    severity=Severity.MEDIUM,
                    title=f"Private entitlement: {key}",
                    description=(
                        f"The app uses private entitlement '{key}'. Private entitlements "
                        f"are not intended for App Store apps and may indicate "
                        f"enterprise/jailbreak-specific behavior."
                    ),
                    location=f"Entitlements: {key}",
                    evidence_static=f"{key} = {entitlements[key]}",
                ))

        return findings
