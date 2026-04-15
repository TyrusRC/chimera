import pytest
from pathlib import Path
from chimera.vuln.rules.manifest import ManifestAnalyzer
from chimera.vuln.rules.base import ScanContext


@pytest.fixture
def manifest_xml():
    manifest_path = Path(__file__).parent.parent.parent / "fixtures" / "sample_manifest.xml"
    return manifest_path.read_text()


@pytest.fixture
def context(manifest_xml):
    return ScanContext(platform="android", manifest_xml=manifest_xml)


class TestManifestAnalyzer:
    async def test_detects_exported_activity_without_permission(self, context):
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(context)
        ipc_001 = [f for f in findings if f.rule_id == "IPC-001"]
        # ExportedActivity and ExportedReceiver and DataProvider are exported without permission
        # BackgroundService has a permission so it should NOT be flagged
        exported_names = [f.location for f in ipc_001]
        assert any("ExportedActivity" in loc for loc in exported_names)
        assert any("ExportedReceiver" in loc for loc in exported_names)
        assert any("DataProvider" in loc for loc in exported_names)
        assert not any("BackgroundService" in loc for loc in exported_names)

    async def test_detects_backup_enabled(self, context):
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(context)
        data_003 = [f for f in findings if f.rule_id == "DATA-003"]
        assert len(data_003) == 1

    async def test_detects_debuggable(self, context):
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(context)
        debuggable = [f for f in findings if "debuggable" in f.title.lower()]
        assert len(debuggable) == 1

    async def test_detects_cleartext_traffic(self, context):
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(context)
        cleartext = [f for f in findings if f.rule_id == "NET-002"]
        assert len(cleartext) == 1

    async def test_detects_deeplink_schemes(self, context):
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(context)
        deeplink = [f for f in findings if f.rule_id == "IPC-006"]
        assert len(deeplink) >= 1
        assert any("vulnerable://callback" in f.description for f in deeplink)

    async def test_skips_non_android(self):
        ctx = ScanContext(platform="ios", manifest_xml=None)
        analyzer = ManifestAnalyzer()
        findings = await analyzer.scan(ctx)
        assert len(findings) == 0
