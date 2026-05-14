"""Unit tests for the CVSS finding builder."""
from pathlib import Path

import pytest

from chimera.detection_engineering.cvss_findings import (
    Finding, build_findings_from_chimera, render_findings_markdown,
    severity_for_score,
)
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel


class _StubCache:
    def __init__(self, blobs: dict | None = None):
        self.cache_dir = Path("/tmp/no-such-cache")
        self._blobs = blobs or {}

    def get_json(self, sha, key):
        return self._blobs.get(key)

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _mobile_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="m" * 64, path=Path("/tmp/x.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def _pe_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="p" * 64, path=Path("/tmp/x.exe"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_severity_for_score():
    # FIRST CVSS v3.1 bucketing:
    #   0.0           -> None
    #   0.1  - 3.9    -> Low
    #   4.0  - 6.9    -> Medium
    #   7.0  - 8.9    -> High
    #   9.0  -10.0    -> Critical
    assert severity_for_score(9.5) == "Critical"
    assert severity_for_score(9.0) == "Critical"
    assert severity_for_score(8.9) == "High"
    assert severity_for_score(7.0) == "High"
    assert severity_for_score(6.9) == "Medium"
    assert severity_for_score(4.0) == "Medium"
    assert severity_for_score(3.9) == "Low"
    assert severity_for_score(0.5) == "Low"
    # Score 0.0 now maps to "None" per FIRST CVSS v3.1 spec (was previously
    # reported as "Informational" — that label is still used for non-CVSS
    # report categories but no longer derives from a zero score).
    assert severity_for_score(0.0) == "None"


@pytest.mark.parametrize("score,expected", [
    (0.0, "None"),
    (0.1, "Low"),
    (3.9, "Low"),
    (4.0, "Medium"),
    (6.9, "Medium"),
    (7.0, "High"),
    (8.9, "High"),
    (9.0, "Critical"),
    (10.0, "Critical"),
])
def test_severity_for_score_buckets_per_cvss_v31(score, expected):
    assert severity_for_score(score) == expected


def test_pe_returns_no_findings():
    """Auto-stub mapping is mobile-only for now."""
    m = _pe_model()
    out = build_findings_from_chimera(m, _StubCache())
    assert out == []


def test_clean_mobile_emits_resilience_and_pinning_findings():
    """A clean (no protections) mobile binary should produce both
    Missing-Resilience AND No-SSL-Pinning findings."""
    m = _mobile_model()
    out = build_findings_from_chimera(m, _StubCache())
    ids = {f.finding_id for f in out}
    assert "CHIMERA-RESILIENCE-001" in ids
    assert "CHIMERA-NETWORK-001" in ids


def test_resilience_present_skips_finding():
    m = _mobile_model()
    cache = _StubCache({
        "protection_profile": {"root_detection": True, "anti_debug": True, "ssl_pinning": True},
    })
    out = build_findings_from_chimera(m, cache)
    ids = {f.finding_id for f in out}
    assert "CHIMERA-RESILIENCE-001" not in ids
    assert "CHIMERA-NETWORK-001" not in ids


def test_obfuscation_yields_informational_finding():
    m = _mobile_model()
    cache = _StubCache({
        "protection_profile": {"root_detection": True, "anti_debug": True, "ssl_pinning": True},
        "native_protection": {"packer": "Bangcle"},
    })
    out = build_findings_from_chimera(m, cache)
    obf = next(f for f in out if f.finding_id == "CHIMERA-CODE-001")
    assert obf.severity == "Informational"
    assert obf.cvss_base_score == 0.0


def test_finding_serializes_to_dict():
    f = Finding(
        finding_id="X-1", title="t", severity="High",
        cvss_vector="CVSS:3.1/AV:N", cvss_base_score=7.5,
    )
    d = f.to_dict()
    assert d["finding_id"] == "X-1"
    assert d["cvss_base_score"] == 7.5


def test_render_markdown_includes_table_and_sections():
    findings = [
        Finding(finding_id="X-1", title="Test", severity="High",
                cvss_vector="CVSS:3.1/...", cvss_base_score=7.5,
                masvs_id="MASVS-NETWORK", description="d",
                evidence=["e1"], recommendation="r"),
    ]
    md = render_findings_markdown(findings)
    assert "| X-1 |" in md
    assert "### X-1 — Test" in md
    assert "**Severity:**" in md
    assert "MASVS-NETWORK" in md


def test_render_markdown_empty():
    md = render_findings_markdown([])
    assert "No findings" in md
