"""CVSS v3.1 finding model and auto-stub builder.

We deliberately don't ship a full CVSS calculator. Each detection-driven
finding gets a SUGGESTED vector + base-score bucket; analysts refine
during the engagement. The output schema is PwnDoc/SysReptor-friendly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# CVSS v3.1 severity buckets per FIRST spec
def severity_for_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


@dataclass
class Finding:
    """One pentest finding, ready for export to PwnDoc/SysReptor/MD."""
    finding_id: str
    title: str
    severity: str                       # Critical/High/Medium/Low/Informational
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


# Suggested CVSS vectors and scores for common Chimera detections.
# These are STARTING POINTS — analysts must verify exploitability and
# adjust based on the engagement context.

_VECTOR_MISSING_RESILIENCE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # 6.7 Medium
_VECTOR_MISSING_PINNING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"     # 4.7 Medium
_VECTOR_HARDCODED_SECRET = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"    # 6.2 Medium
_VECTOR_OUTDATED_SDK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"        # 5.4 Medium
_VECTOR_OBFUSCATION_PRESENT = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0 Informational


def build_findings_from_chimera(model, cache) -> list[Finding]:
    """Generate auto-stub findings from existing Chimera detections.

    Maps:
      * RESILIENCE controls absent → Missing-Resilience finding (Medium).
      * SSL pinning absent on a mobile binary → Insecure-TLS finding (Medium).
      * Obfuscation/packer present → Informational finding (review limits).

    Each returned Finding is a DRAFT — title/desc are filled, but the
    analyst must validate exploitability before reporting.
    """
    if not model.binary.format.is_mobile:
        return []   # mobile-only mapping for now

    sha = model.binary.sha256
    findings: list[Finding] = []

    pp = cache.get_json(sha, "protection_profile") or {}
    native_pp = cache.get_json(sha, "native_protection") or {}

    # Missing resilience
    has_root = bool(pp.get("root_detection") or pp.get("root_detected"))
    has_anti_debug = bool(pp.get("anti_debug") or pp.get("anti_debug_detected") or native_pp.get("has_anti_debug"))
    if not (has_root or has_anti_debug):
        findings.append(Finding(
            finding_id="CHIMERA-RESILIENCE-001",
            title="Missing runtime resilience controls",
            severity="Medium",
            cvss_vector=_VECTOR_MISSING_RESILIENCE,
            cvss_base_score=6.7,
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
            severity="Medium",
            cvss_vector=_VECTOR_MISSING_PINNING,
            cvss_base_score=4.7,
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
