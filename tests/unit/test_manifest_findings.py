from __future__ import annotations
from pathlib import Path

from chimera.detection_engineering.manifest_findings import (
    build_findings_from_models,
)
from chimera.parsers.android_manifest import parse_manifest
from chimera.parsers.network_security_config import parse_nsc

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"
NSC_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nsc"


def _ids(findings):
    return [f.finding_id for f in findings]


def test_debuggable_finding_emitted():
    manifest = parse_manifest(FIXTURES / "debuggable.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    ids = _ids(findings)
    assert "MANIFEST-DEBUGGABLE" in ids
    f = next(f for f in findings if f.finding_id == "MANIFEST-DEBUGGABLE")
    assert f.severity == "High"
    assert f.masvs_id == "MASVS-RESILIENCE"
    assert any("AndroidManifest.xml:" in e for e in f.evidence)


def test_allowbackup_finding_emitted_when_no_full_backup_content():
    manifest = parse_manifest(FIXTURES / "allowbackup.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    assert "MANIFEST-BACKUP" in _ids(findings)


def test_clean_manifest_emits_no_findings():
    manifest = parse_manifest(FIXTURES / "clean.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    assert findings == []


def test_cleartext_explicit_true_emits_finding():
    manifest = parse_manifest(FIXTURES / "cleartext_attr.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    ids = _ids(findings)
    assert "MANIFEST-CLEARTEXT" in ids


def test_cleartext_default_true_for_old_target_sdk():
    # exported_no_perm.xml has targetSdk=33 with no usesCleartextTraffic →
    # default since API 28 is FALSE → no finding.
    manifest = parse_manifest(FIXTURES / "exported_no_perm.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    assert "MANIFEST-CLEARTEXT" not in _ids(findings)


def test_exported_component_without_permission_emits_finding():
    manifest = parse_manifest(FIXTURES / "exported_no_perm.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    matches = [f for f in findings if f.finding_id == "MANIFEST-EXPORTED"]
    # .Pub activity is exported=true with no permission; .Svc is implicit-export
    # via intent-filter with no permission; .P provider has explicit permission so OK.
    assert len(matches) == 2
    titles = {f.title for f in matches}
    assert any(".Pub" in e for f in matches for e in f.evidence)
    assert any(".Svc" in e for f in matches for e in f.evidence)


def test_nsc_cleartext_permitted_finding():
    manifest = parse_manifest(FIXTURES / "clean.xml")
    nsc = parse_nsc(NSC_FIXTURES / "cleartext_permitted.xml")
    findings = build_findings_from_models(manifest, nsc=nsc)
    ids = _ids(findings)
    assert "NSC-CLEARTEXT-PERMITTED" in ids
    f = next(f for f in findings if f.finding_id == "NSC-CLEARTEXT-PERMITTED")
    assert any("network_security_config.xml:" in e for e in f.evidence)


def test_nsc_user_ca_trusted_finding():
    manifest = parse_manifest(FIXTURES / "clean.xml")
    nsc = parse_nsc(NSC_FIXTURES / "user_ca_trusted.xml")
    findings = build_findings_from_models(manifest, nsc=nsc)
    assert "NSC-USER-CA-TRUSTED" in _ids(findings)


def test_nsc_clean_emits_no_nsc_findings():
    manifest = parse_manifest(FIXTURES / "clean.xml")
    nsc = parse_nsc(NSC_FIXTURES / "clean.xml")
    findings = build_findings_from_models(manifest, nsc=nsc)
    nsc_ids = [i for i in _ids(findings) if i.startswith("NSC-")]
    assert nsc_ids == []
