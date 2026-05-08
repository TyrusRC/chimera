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

    return findings
