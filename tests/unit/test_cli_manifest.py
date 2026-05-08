from __future__ import annotations
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from chimera.cli import main
from chimera.detection_engineering.cvss_findings import Finding
from chimera.parsers.android_manifest import parse_manifest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


def test_manifest_cmd_prints_findings_for_debuggable_apk(tmp_path):
    """The CLI invokes parse_manifest + build_findings_from_models on a cached
    project. We mock the engine/cache lookup but exercise the real detector."""
    from chimera.detection_engineering.manifest_findings import build_findings_from_models

    manifest = parse_manifest(FIXTURES / "debuggable.xml")
    findings = build_findings_from_models(manifest, nsc=None)
    assert any(f.finding_id == "MANIFEST-DEBUGGABLE" for f in findings)

    runner = CliRunner()
    fake_cache = MagicMock()
    fake_cache.get.side_effect = lambda sha, key: (
        (FIXTURES / "debuggable.xml").read_bytes() if key == "manifest_xml" else None
    )

    fake_apk = tmp_path / "fake.apk"
    fake_apk.write_bytes(b"PK\x03\x04stub")

    with patch("chimera.cli._load_cache_and_sha", return_value=(fake_cache, "deadbeef" * 8)):
        result = runner.invoke(main, ["manifest", str(fake_apk)])

    assert result.exit_code == 0, result.output
    assert "MANIFEST-DEBUGGABLE" in result.output
    assert "AndroidManifest.xml:" in result.output
