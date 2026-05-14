"""CVSS v3.1 finding model and auto-stub builder.

We deliberately don't ship a full CVSS calculator. Each detection-driven
finding gets a SUGGESTED vector + base-score bucket; analysts refine
during the engagement. The output schema is PwnDoc/SysReptor-friendly.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional


# CVSS v3.1 severity buckets per FIRST spec.
# Boundaries are inclusive at the lower end:
#   0.0           -> None
#   0.1  - 3.9    -> Low
#   4.0  - 6.9    -> Medium
#   7.0  - 8.9    -> High
#   9.0  -10.0    -> Critical
def severity_for_score(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_from_vector(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string.

    Vector format: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N'

    Implementation follows the FIRST CVSS v3.1 specification:
    https://www.first.org/cvss/v3.1/specification-document
    """
    parts = dict(seg.split(":", 1) for seg in vector.split("/")[1:])
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
    ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
    scope_changed = parts.get("S", "U") == "C"
    pr_map = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    pr = pr_map["C" if scope_changed else "U"][parts["PR"]]
    ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
    c = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["C"]]
    i = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["I"]]
    a = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if not scope_changed:
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    # Round up to one decimal place per CVSS v3.1 roundup definition.
    return math.ceil(base * 10) / 10


@dataclass
class Finding:
    """One pentest finding, ready for export to PwnDoc/SysReptor/MD."""
    finding_id: str
    title: str
    severity: str                       # Critical/High/Medium/Low/None or Informational
    cvss_vector: str                    # e.g., "CVSS:3.1/AV:N/AC:L/..."
    cvss_base_score: float
    masvs_id: Optional[str] = None      # e.g., "MASVS-RESILIENCE"
    cwe_id: Optional[str] = None        # e.g., "CWE-489"
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_vector": self.cvss_vector,
            "cvss_base_score": self.cvss_base_score,
            "masvs_id": self.masvs_id,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "recommendation": self.recommendation,
            "references": self.references,
        }


# Suggested CVSS vectors for common Chimera detections.
# These are STARTING POINTS — analysts must verify exploitability and
# adjust based on the engagement context. The score + severity are
# derived from the vector so they cannot drift apart.

_VECTOR_MISSING_RESILIENCE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
_SCORE_MISSING_RESILIENCE = score_from_vector(_VECTOR_MISSING_RESILIENCE)
_SEVERITY_MISSING_RESILIENCE = severity_for_score(_SCORE_MISSING_RESILIENCE)

_VECTOR_MISSING_PINNING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
_SCORE_MISSING_PINNING = score_from_vector(_VECTOR_MISSING_PINNING)
_SEVERITY_MISSING_PINNING = severity_for_score(_SCORE_MISSING_PINNING)

_VECTOR_HARDCODED_SECRET = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
_SCORE_HARDCODED_SECRET = score_from_vector(_VECTOR_HARDCODED_SECRET)
_SEVERITY_HARDCODED_SECRET = severity_for_score(_SCORE_HARDCODED_SECRET)

_VECTOR_OUTDATED_SDK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
_SCORE_OUTDATED_SDK = score_from_vector(_VECTOR_OUTDATED_SDK)
_SEVERITY_OUTDATED_SDK = severity_for_score(_SCORE_OUTDATED_SDK)

_VECTOR_OBFUSCATION_PRESENT = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
_SCORE_OBFUSCATION_PRESENT = score_from_vector(_VECTOR_OBFUSCATION_PRESENT)
_SEVERITY_OBFUSCATION_PRESENT = severity_for_score(_SCORE_OBFUSCATION_PRESENT)


def build_findings_from_chimera(model, cache) -> list[Finding]:
    """Generate auto-stub findings from existing Chimera detections.

    Maps:
      * RESILIENCE controls absent → Missing-Resilience finding (Medium).
      * SSL pinning absent on a mobile binary → Insecure-TLS finding (Medium).
      * Obfuscation/packer present → Informational finding (review limits).

    Each returned Finding is a DRAFT — title/desc are filled, but the
    analyst must validate exploitability before reporting.
    """
    findings: list[Finding] = []

    # Manifest + NSC findings (Android only).
    if getattr(model.binary, "platform", None) == "android":
        try:
            from chimera.parsers.android_manifest import parse_manifest
            from chimera.parsers.network_security_config import parse_nsc
            from chimera.detection_engineering.manifest_findings import (
                build_findings_from_models,
            )
            import tempfile
            from pathlib import Path as _P
            mxml = cache.get(model.binary.sha256, "manifest_xml")
            if mxml:
                with tempfile.TemporaryDirectory() as td:
                    mp = _P(td) / "AndroidManifest.xml"
                    mp.write_bytes(mxml)
                    manifest_model = parse_manifest(mp)
                    nsc_model = None
                    nxml = cache.get(model.binary.sha256, "nsc_xml")
                    if nxml:
                        np = _P(td) / "network_security_config.xml"
                        np.write_bytes(nxml)
                        nsc_model = parse_nsc(np)
                    findings.extend(
                        build_findings_from_models(manifest_model, nsc=nsc_model)
                    )
        except Exception:
            pass

    if not model.binary.format.is_mobile:
        return findings   # mobile-only mapping for the rest

    sha = model.binary.sha256

    pp = cache.get_json(sha, "protection_profile") or {}
    native_pp = cache.get_json(sha, "native_protection") or {}

    # Missing resilience
    has_root = bool(pp.get("root_detection") or pp.get("root_detected"))
    has_anti_debug = bool(pp.get("anti_debug") or pp.get("anti_debug_detected") or native_pp.get("has_anti_debug"))
    if not (has_root or has_anti_debug):
        findings.append(Finding(
            finding_id="CHIMERA-RESILIENCE-001",
            title="Missing runtime resilience controls",
            severity=_SEVERITY_MISSING_RESILIENCE,
            cvss_vector=_VECTOR_MISSING_RESILIENCE,
            cvss_base_score=_SCORE_MISSING_RESILIENCE,
            masvs_id="MASVS-RESILIENCE",
            cwe_id="CWE-693",  # Protection Mechanism Failure
            description=(
                "The application binary does not exhibit common runtime resilience "
                "patterns (root/jailbreak detection, anti-debug). An attacker with "
                "physical access can attach a debugger or run on a rooted device "
                "without the app reacting."
            ),
            evidence=[
                "No root_detection patterns in ProtectionDetector output.",
                "No anti_debug patterns in ProtectionDetector / NativeProtection output.",
            ],
            recommendation=(
                "Add layered runtime self-protection: root/jailbreak detection, "
                "anti-debug, anti-Frida, and tamper detection. Combine with "
                "code obfuscation to raise the bar."
            ),
            references=[
                "https://mas.owasp.org/MASVS/06-MASVS-RESILIENCE/",
            ],
        ))

    # Missing SSL pinning
    has_pinning = bool(pp.get("ssl_pinning") or pp.get("ssl_pinning_detected"))
    if not has_pinning:
        findings.append(Finding(
            finding_id="CHIMERA-NETWORK-001",
            title="No SSL pinning detected",
            severity=_SEVERITY_MISSING_PINNING,
            cvss_vector=_VECTOR_MISSING_PINNING,
            cvss_base_score=_SCORE_MISSING_PINNING,
            masvs_id="MASVS-NETWORK",
            cwe_id="CWE-295",  # Improper Certificate Validation
            description=(
                "No certificate-pinning patterns were detected in the binary. "
                "Without pinning, an attacker who controls the device's trust "
                "store (rooted device, custom CA) can intercept and modify "
                "TLS traffic to backend services."
            ),
            evidence=[
                "ProtectionDetector found no CertificatePinner / TrustKit / "
                "BoringSSL pinning patterns.",
            ],
            recommendation=(
                "Implement certificate or public-key pinning for all backend "
                "API calls. Validate pinning under runtime hooking attacks."
            ),
            references=[
                "https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/",
            ],
        ))

    # Obfuscation present (informational — limits assessment quality)
    if native_pp.get("packer") or native_pp.get("obfuscation"):
        findings.append(Finding(
            finding_id="CHIMERA-CODE-001",
            title="Obfuscation / packer present (informational)",
            severity="Informational",
            cvss_vector=_VECTOR_OBFUSCATION_PRESENT,
            cvss_base_score=0.0,
            masvs_id="MASVS-CODE",
            description=(
                "The binary uses an obfuscator or packer "
                f"({native_pp.get('packer') or 'detected'}). Static analysis "
                "coverage is limited; deeper findings may require manual "
                "deobfuscation or runtime tracing."
            ),
            evidence=[
                f"native_protection.packer = {native_pp.get('packer')!r}",
            ],
            recommendation=(
                "Acknowledge obfuscation as defense-in-depth. Verify under "
                "instrumentation that critical security controls are not "
                "bypassed by the obfuscator's runtime."
            ),
        ))

    return findings


def render_findings_markdown(findings: list[Finding]) -> str:
    """Render findings as a Markdown table + per-finding sections.

    PwnDoc/SysReptor analysts can paste this directly into their template.
    """
    if not findings:
        return "_No findings auto-generated._\n"
    lines: list[str] = []
    lines.append("| ID | Title | Severity | CVSS | MASVS |")
    lines.append("|----|-------|----------|------|-------|")
    for f in findings:
        lines.append(
            f"| {f.finding_id} | {f.title} | {f.severity} | "
            f"{f.cvss_base_score} | {f.masvs_id or '—'} |"
        )
    lines.append("")
    for f in findings:
        lines.append(f"### {f.finding_id} — {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity} ({f.cvss_base_score})")
        lines.append(f"- **CVSS vector:** `{f.cvss_vector}`")
        if f.masvs_id:
            lines.append(f"- **MASVS:** {f.masvs_id}")
        if f.cwe_id:
            lines.append(f"- **CWE:** {f.cwe_id}")
        lines.append("")
        lines.append("**Description**")
        lines.append("")
        lines.append(f.description)
        if f.evidence:
            lines.append("")
            lines.append("**Evidence**")
            lines.append("")
            for e in f.evidence:
                lines.append(f"- {e}")
        if f.reproduction_steps:
            lines.append("")
            lines.append("**Reproduction**")
            lines.append("")
            for i, s in enumerate(f.reproduction_steps, 1):
                lines.append(f"{i}. {s}")
        if f.recommendation:
            lines.append("")
            lines.append("**Recommendation**")
            lines.append("")
            lines.append(f.recommendation)
        if f.references:
            lines.append("")
            lines.append("**References**")
            lines.append("")
            for ref in f.references:
                lines.append(f"- {ref}")
        lines.append("")
    return "\n".join(lines)
