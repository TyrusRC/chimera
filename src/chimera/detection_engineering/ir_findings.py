"""IR finding model + auto-stub builder from cached memory analysis.

Sibling to `cvss_findings.py` but for forensic observations rather than
pentest findings. Each finding has a category (process_anomaly,
kernel_rootkit, persistence, network_anomaly, malicious_memory) and a
severity bucket. Auto-stub builder turns cached Volatility output into
draft findings the analyst then refines.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Severity buckets
SEV_CRITICAL = "Critical"
SEV_HIGH = "High"
SEV_MEDIUM = "Medium"
SEV_LOW = "Low"
SEV_INFO = "Informational"

# Category vocabulary
CAT_PROCESS_ANOMALY = "process_anomaly"
CAT_KERNEL_ROOTKIT = "kernel_rootkit"
CAT_PERSISTENCE = "persistence"
CAT_NETWORK_ANOMALY = "network_anomaly"
CAT_MALICIOUS_MEMORY = "malicious_memory"


@dataclass
class IRFinding:
    finding_id: str
    title: str
    category: str
    severity: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)  # ATT&CK technique IDs
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "title": self.title,
            "category": self.category, "severity": self.severity,
            "description": self.description, "evidence": self.evidence,
            "mitre_attack": self.mitre_attack,
            "recommendation": self.recommendation,
        }


def _next_id(prefix: str, counter: list[int]) -> str:
    counter[0] += 1
    return f"{prefix}-{counter[0]:03d}"


def build_ir_findings(model, cache) -> list[IRFinding]:
    """Auto-stub IR findings from cached memory-analysis output.

    Mappings:
      * Hooked syscalls → CRITICAL kernel_rootkit (T1014)
      * Hidden kernel modules → HIGH kernel_rootkit (T1014)
      * Malfind RWX VMAs → HIGH malicious_memory (T1055)
      * Memory persistence findings (cron/systemd/etc.) → MEDIUM persistence (T1543)
      * Network connections to public IPs → LOW network_anomaly (T1071)
    """
    if not model.binary.format.is_memory_image:
        return []

    sha = model.binary.sha256
    findings: list[IRFinding] = []
    counter = [0]

    # Hooked syscalls (kernel rootkit)
    chk = cache.get_json(sha, "vol_check_syscall") or {}
    hooked = [r for r in (chk.get("rows") or [])
              if r.get("handler_symbol") in (None, "", "UNKNOWN")]
    if hooked:
        findings.append(IRFinding(
            finding_id=_next_id("CHIMERA-IR", counter),
            title="Unresolved syscall handlers (rootkit indicator)",
            category=CAT_KERNEL_ROOTKIT,
            severity=SEV_CRITICAL,
            description=(
                f"{len(hooked)} syscall slot(s) point to handlers that don't "
                f"resolve to known kernel symbols. Common rootkit indicator: "
                f"the syscall table has been hooked to redirect calls."
            ),
            evidence=[f"syscall #{r.get('index')} '{r.get('name')}' → {r.get('handler_addr')}"
                      for r in hooked[:10]],
            mitre_attack=["T1014"],
            recommendation=(
                "Investigate the kernel's syscall table for hooks. Compare "
                "handler addresses against the kernel's known-good symbols "
                "from a clean kernel of the same version."
            ),
        ))

    # Hidden modules (Check_modules)
    chm = cache.get_json(sha, "vol_check_modules") or {}
    hidden = chm.get("rows") or []
    if hidden:
        findings.append(IRFinding(
            finding_id=_next_id("CHIMERA-IR", counter),
            title="Hidden kernel modules in memory",
            category=CAT_KERNEL_ROOTKIT,
            severity=SEV_HIGH,
            description=(
                f"{len(hidden)} kernel module(s) appear in the in-memory "
                f"module list but are absent from /proc/modules — suggesting "
                f"a userland-visible filter has been installed."
            ),
            evidence=[f"{r.get('name')} @ {r.get('address')}" for r in hidden[:10]],
            mitre_attack=["T1014"],
            recommendation=(
                "Quarantine the host. Compare /proc/modules with the in-memory "
                "list at acquisition; reboot to a clean kernel; preserve the "
                "memory image for downstream analysis."
            ),
        ))

    # Malfind hits
    mf = cache.get_json(sha, "vol_malfind") or {}
    rwx = [r for r in (mf.get("rows") or [])
           if r.get("protection", "").lower().startswith("rwx")
              or "rwx" in r.get("protection", "").lower()]
    if rwx:
        findings.append(IRFinding(
            finding_id=_next_id("CHIMERA-IR", counter),
            title="RWX memory regions in user processes",
            category=CAT_MALICIOUS_MEMORY,
            severity=SEV_HIGH,
            description=(
                f"{len(rwx)} VMA region(s) with read+write+execute permissions "
                f"detected. RWX is rare in legitimate code; common in shellcode "
                f"or unpacker stubs."
            ),
            evidence=[f"PID {r.get('pid')} '{r.get('process')}' "
                      f"{r.get('start_addr')}–{r.get('end_addr')} ({r.get('protection')})"
                      for r in rwx[:10]],
            mitre_attack=["T1055"],
            recommendation=(
                "Dump each RWX region (`vol -f IMAGE linux.proc.Maps --pid PID --dump`) "
                "and analyze the contents. JIT runtimes (V8, OpenJDK) legitimately "
                "produce RWX; rule those out before declaring malicious."
            ),
        ))

    # Persistence findings
    persistence = cache.get_json(sha, "memory_persistence") or {}
    pf_rows = persistence.get("findings") or []
    if pf_rows:
        findings.append(IRFinding(
            finding_id=_next_id("CHIMERA-IR", counter),
            title="Persistence-relevant files cached in memory",
            category=CAT_PERSISTENCE,
            severity=SEV_MEDIUM,
            description=(
                f"{len(pf_rows)} file path(s) matching cron/systemd/init.d/"
                f"LD_PRELOAD/etc. patterns were cached at acquisition time. "
                f"Review each for newly-installed or attacker-modified entries."
            ),
            evidence=[f"[{r.get('category')}] {r.get('path')}" for r in pf_rows[:15]],
            mitre_attack=["T1543", "T1574.006"],
            recommendation=(
                "Compare each path against known baselines. Recover file content "
                "via `linux.pagecache.RecoverFs` and parse with the chimera cron/"
                "systemd parsers; check for unauthorised users / ExecStart paths."
            ),
        ))

    # Network anomalies — established connections to non-RFC1918 hosts
    netstat = cache.get_json(sha, "vol_netstat") or {}
    public_conns = []
    for row in (netstat.get("rows") or []):
        # parse_netstat dicts already have local/remote keys
        remote = row.get("remote", "")
        if not remote or remote.startswith(("0.0.0.0", "127.", "10.",
                                             "192.168.", "172.16.", "172.17.",
                                             "172.18.", "172.19.", "172.20.",
                                             "172.21.", "172.22.", "172.23.",
                                             "172.24.", "172.25.", "172.26.",
                                             "172.27.", "172.28.", "172.29.",
                                             "172.30.", "172.31.", "169.254.",
                                             "::", "fe80:", "*")):
            continue
        if row.get("state") == "ESTABLISHED":
            public_conns.append(row)
    if public_conns:
        findings.append(IRFinding(
            finding_id=_next_id("CHIMERA-IR", counter),
            title="Established connections to non-private addresses",
            category=CAT_NETWORK_ANOMALY,
            severity=SEV_LOW,
            description=(
                f"{len(public_conns)} ESTABLISHED connection(s) to public "
                f"IPs at acquisition. Many are legitimate; audit each for "
                f"unexpected egress."
            ),
            evidence=[f"PID {r.get('pid')} '{r.get('process')}' → {r.get('remote')}"
                      for r in public_conns[:10]],
            mitre_attack=["T1071"],
            recommendation=(
                "Cross-reference each remote endpoint against threat-intel "
                "feeds. Investigate any outbound to unfamiliar ASNs."
            ),
        ))

    return findings


def render_ir_findings_markdown(findings: list[IRFinding]) -> str:
    """Render findings as a Markdown report (table + per-finding sections)."""
    if not findings:
        return "_No IR findings auto-generated._\n"
    lines: list[str] = []
    lines.append("| ID | Title | Category | Severity | ATT&CK |")
    lines.append("|----|-------|----------|----------|--------|")
    for f in findings:
        attack = ", ".join(f.mitre_attack) if f.mitre_attack else "—"
        lines.append(f"| {f.finding_id} | {f.title} | {f.category} | {f.severity} | {attack} |")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.finding_id} — {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **Category:** {f.category}")
        if f.mitre_attack:
            lines.append(f"- **ATT&CK:** {', '.join(f.mitre_attack)}")
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
        if f.recommendation:
            lines.append("")
            lines.append("**Recommendation**")
            lines.append("")
            lines.append(f.recommendation)
        lines.append("")
    return "\n".join(lines)
