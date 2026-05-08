from __future__ import annotations
from pathlib import Path

from chimera.detection_engineering.manifest_findings import (
    build_findings_from_models,
)
from chimera.parsers.android_manifest import parse_manifest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


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
