"""Android manifest analysis — exported components, backup, debuggable, cleartext, deeplinks."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from chimera.vuln.finding import Finding, Severity
from chimera.vuln.masvs import masvs_for_rule
from chimera.vuln.rules.base import VulnRule, ScanContext

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element: ET.Element, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


class ManifestAnalyzer(VulnRule):
    def rule_id(self) -> str:
        return "MANIFEST"

    def title(self) -> str:
        return "Android Manifest Analyzer"

    def severity_default(self) -> str:
        return "medium"

    def platforms(self) -> list[str]:
        return ["android"]

    async def scan(self, context: ScanContext) -> list[Finding]:
        if context.platform != "android" or not context.manifest_xml:
            return []

        try:
            root = ET.fromstring(context.manifest_xml)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_exported_components(root))
        findings.extend(self._check_backup(root))
        findings.extend(self._check_debuggable(root))
        findings.extend(self._check_cleartext(root))
        findings.extend(self._check_deeplinks(root))

        # Apply MASVS mapping to all findings
        for f in findings:
            m = masvs_for_rule(f.rule_id)
            f.masvs_category = m["category"]
            f.mastg_test = m["mastg_test"]

        return findings

    def _check_exported_components(self, root: ET.Element) -> list[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        component_tags = ["activity", "receiver", "provider", "service"]
        for tag in component_tags:
            for comp in app.findall(tag):
                exported = _attr(comp, "exported")
                permission = _attr(comp, "permission")
                name = _attr(comp, "name") or "unknown"

                # exported=true without permission
                if exported == "true" and not permission:
                    findings.append(Finding(
                        rule_id="IPC-001",
                        severity=Severity.HIGH,
                        title=f"Exported {tag} without permission: {name}",
                        description=(
                            f"The {tag} '{name}' is exported without any permission requirement. "
                            f"Any app on the device can interact with it."
                        ),
                        location=f"AndroidManifest.xml: {name}",
                        evidence_static=f'android:exported="true" with no android:permission',
                    ))

                # Components with intent-filters are implicitly exported (pre-Android 12)
                if exported is None and comp.findall("intent-filter"):
                    if not permission:
                        findings.append(Finding(
                            rule_id="IPC-001",
                            severity=Severity.MEDIUM,
                            title=f"Implicitly exported {tag}: {name}",
                            description=(
                                f"The {tag} '{name}' has intent-filters but no explicit "
                                f"exported=false, making it implicitly exported on older Android."
                            ),
                            location=f"AndroidManifest.xml: {name}",
                            evidence_static="Has intent-filter without explicit exported attribute",
                        ))

        return findings

    def _check_backup(self, root: ET.Element) -> list[Finding]:
        app = root.find("application")
        if app is None:
            return []
        allow_backup = _attr(app, "allowBackup")
        if allow_backup == "true":
            return [Finding(
                rule_id="DATA-003",
                severity=Severity.MEDIUM,
                title="Application backup enabled",
                description=(
                    "android:allowBackup is true. An attacker with physical access "
                    "can extract app data via adb backup."
                ),
                location="AndroidManifest.xml: <application>",
                evidence_static='android:allowBackup="true"',
            )]
        return []

    def _check_debuggable(self, root: ET.Element) -> list[Finding]:
        app = root.find("application")
        if app is None:
            return []
        debuggable = _attr(app, "debuggable")
        if debuggable == "true":
            return [Finding(
                rule_id="DATA-003",
                severity=Severity.HIGH,
                title="Application is debuggable",
                description=(
                    "android:debuggable is true. This allows attaching a debugger "
                    "and accessing the app sandbox without root."
                ),
                location="AndroidManifest.xml: <application>",
                evidence_static='android:debuggable="true"',
                business_impact="Full app sandbox access without root",
            )]
        return []

    def _check_cleartext(self, root: ET.Element) -> list[Finding]:
        app = root.find("application")
        if app is None:
            return []
        cleartext = _attr(app, "usesCleartextTraffic")
        if cleartext == "true":
            return [Finding(
                rule_id="NET-002",
                severity=Severity.MEDIUM,
                title="Cleartext traffic allowed globally",
                description=(
                    "android:usesCleartextTraffic is true. The app can send "
                    "sensitive data over unencrypted HTTP."
                ),
                location="AndroidManifest.xml: <application>",
                evidence_static='android:usesCleartextTraffic="true"',
            )]
        return []

    def _check_deeplinks(self, root: ET.Element) -> list[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        for activity in app.findall("activity"):
            name = _attr(activity, "name") or "unknown"
            for intent_filter in activity.findall("intent-filter"):
                for data in intent_filter.findall("data"):
                    scheme = _attr(data, "scheme")
                    host = _attr(data, "host")
                    if scheme and scheme not in ("http", "https"):
                        uri = f"{scheme}://{host}" if host else f"{scheme}://"
                        findings.append(Finding(
                            rule_id="IPC-006",
                            severity=Severity.MEDIUM,
                            title=f"Custom deeplink scheme: {uri}",
                            description=(
                                f"Activity '{name}' handles custom scheme '{uri}'. "
                                f"If parameters are not validated, this can lead to "
                                f"injection attacks via crafted deeplinks."
                            ),
                            location=f"AndroidManifest.xml: {name}",
                            evidence_static=f"scheme={scheme}, host={host}",
                        ))
        return findings
