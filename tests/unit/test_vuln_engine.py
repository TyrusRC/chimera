import pytest
from pathlib import Path
from chimera.vuln.engine import VulnEngine


@pytest.fixture
def sources(tmp_path):
    src = tmp_path / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Bad.java").write_text(
        'public class Bad {\n'
        '    Cipher c = Cipher.getInstance("AES/ECB/NoPadding");\n'
        '}\n'
    )
    return tmp_path / "sources"


class TestVulnEngine:
    async def test_scan_returns_findings(self, sources):
        engine = VulnEngine()
        findings = await engine.scan(
            platform="android",
            jadx_sources_dir=sources,
        )
        assert len(findings) >= 1
        assert any(f.rule_id == "CRYPTO-001" for f in findings)

    async def test_scan_filters_by_platform(self, sources):
        engine = VulnEngine()
        findings = await engine.scan(
            platform="ios",
            jadx_sources_dir=sources,
        )
        # iOS rules that scan Java sources should still find patterns
        # (rules check source content, not platform for source scanning)
        # But manifest rules should not fire
        manifest_findings = [f for f in findings if "Manifest" in f.location]
        assert len(manifest_findings) == 0
