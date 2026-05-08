from __future__ import annotations
from pathlib import Path
from unittest.mock import MagicMock

from chimera.detection_engineering.cvss_findings import build_findings_from_chimera

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


def test_cvss_findings_include_manifest_rules():
    model = MagicMock()
    # Make model.* attribute access not contribute additional findings:
    # build_findings_from_chimera reads protection profile, ssl pinning, etc.
    # We just ensure it doesn't crash and that manifest findings are appended.
    model.binary.platform = "android"

    cache = MagicMock()
    cache.get.side_effect = lambda sha, key: (
        (FIXTURES / "debuggable.xml").read_bytes() if key == "manifest_xml" else None
    )
    model.binary.sha256 = "a" * 64

    findings = build_findings_from_chimera(model, cache)
    ids = {f.finding_id for f in findings}
    assert "MANIFEST-DEBUGGABLE" in ids
