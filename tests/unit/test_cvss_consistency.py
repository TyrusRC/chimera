"""For every manifest finding that declares a CVSS vector, the emitted score
must equal the score computed from the vector, and severity must follow the
recomputed score per FIRST CVSS v3.1 bucketing."""
from __future__ import annotations

from pathlib import Path

import pytest

from chimera.detection_engineering.cvss_findings import (
    score_from_vector,
    severity_for_score,
)
from chimera.detection_engineering.manifest_findings import (
    build_findings_from_models,
)
from chimera.parsers.android_manifest import parse_manifest
from chimera.parsers.network_security_config import parse_nsc


FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"
NSC_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nsc"


def _all_emitted_findings():
    """Drive every manifest + NSC fixture combination so every rule fires."""
    out = []
    # Each manifest fixture, with and without NSCs that trigger NSC rules.
    manifest_files = sorted(FIXTURES.glob("*.xml"))
    nsc_files = [None] + sorted(NSC_FIXTURES.glob("*.xml"))
    for mf in manifest_files:
        manifest = parse_manifest(mf)
        for nf in nsc_files:
            nsc = parse_nsc(nf) if nf is not None else None
            out.extend(build_findings_from_models(manifest, nsc=nsc))
    return out


def test_every_manifest_finding_score_matches_vector():
    findings = _all_emitted_findings()
    # Sanity: we are actually exercising the rules we care about.
    ids = {f.finding_id for f in findings}
    assert "MANIFEST-CLEARTEXT" in ids
    assert "NSC-USER-CA-TRUSTED" in ids

    seen_with_vector = 0
    for f in findings:
        vector = getattr(f, "cvss_vector", None)
        score = getattr(f, "cvss_score", None)
        if score is None:
            score = getattr(f, "cvss_base_score", None)
        severity = getattr(f, "severity", None)
        if vector and score is not None:
            seen_with_vector += 1
            expected_score = score_from_vector(vector)
            assert abs(score - expected_score) < 0.05, (
                f"{f.finding_id}: declared score {score} disagrees "
                f"with vector ({expected_score})"
            )
            assert severity == severity_for_score(expected_score), (
                f"{f.finding_id}: severity {severity} disagrees with "
                f"recomputed {severity_for_score(expected_score)}"
            )
    assert seen_with_vector > 0


def test_score_from_vector_known_examples():
    # Reference values computed using the official FIRST CVSS v3.1
    # calculator (https://www.first.org/cvss/calculator/3.1).

    # MANIFEST-CLEARTEXT vector -> 5.3 Medium.
    s = score_from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N")
    assert abs(s - 5.3) < 0.05
    assert severity_for_score(s) == "Medium"

    # NSC-USER-CA-TRUSTED vector -> 6.8 Medium.
    s = score_from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N")
    assert abs(s - 6.8) < 0.05
    assert severity_for_score(s) == "Medium"

    # MANIFEST-DEBUGGABLE vector -> 7.7 High.
    s = score_from_vector("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert abs(s - 7.7) < 0.05
    assert severity_for_score(s) == "High"

    # Scope-changed example: lateral movement vector (sanity-check that the
    # scope=C branch uses the 1.08 multiplier and PR table swap).
    # CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H -> 9.9 Critical
    s = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert abs(s - 9.9) < 0.05
    assert severity_for_score(s) == "Critical"

    # Vector with no impact -> 0.0 None.
    s = score_from_vector("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert s == 0.0
    assert severity_for_score(s) == "None"
