from __future__ import annotations
from pathlib import Path

import pytest

from chimera.parsers.android_manifest import parse_manifest
from chimera.parsers.network_security_config import parse_nsc
from chimera.detection_engineering.manifest_findings import build_findings_from_models

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_manifest_plus_nsc_findings_combined():
    manifest = parse_manifest(FIXTURES / "manifests" / "debuggable.xml")
    nsc = parse_nsc(FIXTURES / "nsc" / "cleartext_permitted.xml")
    findings = build_findings_from_models(manifest, nsc=nsc)
    ids = {f.finding_id for f in findings}
    # Manifest-side issues
    assert "MANIFEST-DEBUGGABLE" in ids
    assert "MANIFEST-BACKUP" in ids
    # NSC-side issues
    assert "NSC-CLEARTEXT-PERMITTED" in ids
