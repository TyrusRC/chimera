"""Manifest + NSC static finding detector.

Consumes parsed AndroidManifest and (optionally) network_security_config
models and emits Finding objects with file:line evidence. Used by
chimera report and the new chimera manifest CLI subcommand.
"""
from __future__ import annotations

from typing import Optional

from chimera.detection_engineering.cvss_findings import Finding
from chimera.parsers.android_manifest import ManifestModel
from chimera.parsers.network_security_config import NSCModel


_VECTOR_DEBUGGABLE = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.1 High
_VECTOR_BACKUP = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"      # 5.5 Medium
_VECTOR_CLEARTEXT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"   # 4.7 Medium
_VECTOR_EXPORTED = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"    # 5.3 Medium


def build_findings_from_models(
    manifest: ManifestModel,
    nsc: Optional[NSCModel],
) -> list[Finding]:
    findings: list[Finding] = []

    app = manifest.application

    if app.debuggable is True:
        findings.append(Finding(
            finding_id="MANIFEST-DEBUGGABLE",
            title="Application is debuggable in production",
            severity="High",
            cvss_vector=_VECTOR_DEBUGGABLE,
            cvss_base_score=7.1,
            masvs_id="MASVS-RESILIENCE",
            cwe_id="CWE-489",
            description=(
                "android:debuggable=\"true\" allows attackers with adb access to "
                "attach a debugger to the app and read/modify memory at runtime."
            ),
            evidence=[f"AndroidManifest.xml:{app.line} android:debuggable=\"true\""],
            recommendation=(
                "Set android:debuggable=\"false\" or rely on the build-type default "
                "(release builds disable debuggable automatically)."
            ),
        ))

    if app.allow_backup is True and not app.full_backup_content:
        findings.append(Finding(
            finding_id="MANIFEST-BACKUP",
            title="Unrestricted backup allowed",
            severity="Medium",
            cvss_vector=_VECTOR_BACKUP,
            cvss_base_score=5.5,
            masvs_id="MASVS-STORAGE",
            cwe_id="CWE-200",
            description=(
                "allowBackup=\"true\" without fullBackupContent rules lets adb backup "
                "extract the app's private data on devices where USB debugging is enabled."
            ),
            evidence=[f"AndroidManifest.xml:{app.line} android:allowBackup=\"true\""],
            recommendation=(
                "Set allowBackup=\"false\" or supply android:fullBackupContent / "
                "android:dataExtractionRules to exclude sensitive paths."
            ),
        ))

    cleartext = app.uses_cleartext_traffic
    if cleartext is None and (manifest.target_sdk_version or 0) < 28:
        # API 27 and below default to allowing cleartext
        cleartext = True
    if cleartext is True:
        findings.append(Finding(
            finding_id="MANIFEST-CLEARTEXT",
            title="Cleartext HTTP traffic permitted",
            severity="High",
            cvss_vector=_VECTOR_CLEARTEXT,
            cvss_base_score=7.4,
            masvs_id="MASVS-NETWORK",
            cwe_id="CWE-319",
            description=(
                "android:usesCleartextTraffic=\"true\" (or default-true on API <= 27) "
                "allows the app to make plaintext HTTP requests, enabling MITM attacks "
                "on the data plane."
            ),
            evidence=[
                f"AndroidManifest.xml:{app.line} usesCleartextTraffic="
                f"{'true' if app.uses_cleartext_traffic else 'default'}"
            ],
            recommendation=(
                "Set usesCleartextTraffic=\"false\" and supply a network_security_config "
                "with cleartextTrafficPermitted=\"false\"."
            ),
        ))

    for comp in (manifest.activities + manifest.services
                 + manifest.receivers + manifest.providers):
        explicit_export = comp.exported is True
        implicit_export = comp.exported is None and comp.has_intent_filter
        if (explicit_export or implicit_export) and not comp.permission:
            findings.append(Finding(
                finding_id="MANIFEST-EXPORTED",
                title=f"Exported {comp.kind} without permission",
                severity="Medium",
                cvss_vector=_VECTOR_EXPORTED,
                cvss_base_score=5.3,
                masvs_id="MASVS-PLATFORM",
                cwe_id="CWE-926",
                description=(
                    f"The {comp.kind} {comp.name!r} is exported "
                    f"({'explicit' if explicit_export else 'implicit via intent-filter'}) "
                    "and has no android:permission, so any app on the device can invoke it."
                ),
                evidence=[
                    f"AndroidManifest.xml:{comp.line} {comp.kind} {comp.name}"
                ],
                recommendation=(
                    "Set android:exported=\"false\", or define and require an "
                    "android:permission with a signature-level protectionLevel."
                ),
            ))

    return findings
