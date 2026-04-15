import pytest
from pathlib import Path
from chimera.frameworks.react_native import ReactNativeAnalyzer


class TestReactNativeAnalyzer:
    def test_extract_jsc_bundle(self, tmp_path):
        assets = tmp_path / "assets"
        assets.mkdir()
        bundle = assets / "index.android.bundle"
        bundle.write_text(
            'var config = { apiUrl: "https://api.example.com/v2", '
            'debug: true, apiKey: "sk-live-abc123" };\n'
            '__DEV__ = true;\n'
            'AsyncStorage.setItem("auth_token", token);\n'
        )
        analyzer = ReactNativeAnalyzer()
        result = analyzer.analyze_bundle(bundle, variant="jsc")
        assert result["variant"] == "jsc"
        assert len(result["strings_of_interest"]) > 0

    def test_detect_hermes(self, tmp_path):
        bundle = tmp_path / "index.android.bundle"
        bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 100)
        analyzer = ReactNativeAnalyzer()
        assert analyzer.is_hermes(bundle) is True

    def test_detect_jsc(self, tmp_path):
        bundle = tmp_path / "index.android.bundle"
        bundle.write_text("var x = 1;")
        analyzer = ReactNativeAnalyzer()
        assert analyzer.is_hermes(bundle) is False

    def test_extract_security_findings(self, tmp_path):
        assets = tmp_path / "assets"
        assets.mkdir()
        bundle = assets / "index.android.bundle"
        bundle.write_text(
            'AsyncStorage.setItem("password", pw);\n'
            'if (__DEV__) { console.log("debug mode"); }\n'
        )
        analyzer = ReactNativeAnalyzer()
        findings = analyzer.scan_for_issues(bundle)
        assert any("AsyncStorage" in f["pattern"] for f in findings)
        assert any("__DEV__" in f["pattern"] for f in findings)
