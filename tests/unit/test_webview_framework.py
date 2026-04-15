from pathlib import Path
from chimera.frameworks.webview import WebViewFrameworkAnalyzer


class TestWebViewFrameworkAnalyzer:
    def test_find_web_assets(self, tmp_path):
        www = tmp_path / "assets" / "www"
        www.mkdir(parents=True)
        (www / "index.html").write_text("<html><body>app</body></html>")
        (www / "app.js").write_text("var x = 1;")
        analyzer = WebViewFrameworkAnalyzer()
        result = analyzer.find_web_assets(tmp_path)
        assert result["root"] is not None
        assert result["js_file_count"] >= 1

    def test_detect_source_maps(self, tmp_path):
        www = tmp_path / "assets" / "www"
        www.mkdir(parents=True)
        (www / "app.js").write_text("var x = 1;\n//# sourceMappingURL=app.js.map")
        (www / "app.js.map").write_text('{"version":3,"sources":["src/app.ts"]}')
        analyzer = WebViewFrameworkAnalyzer()
        maps = analyzer.find_source_maps(www)
        assert len(maps) >= 1

    def test_extract_strings_from_js(self, tmp_path):
        www = tmp_path / "assets" / "www"
        www.mkdir(parents=True)
        (www / "app.js").write_text(
            'const API = "https://api.example.com";\n'
            'const KEY = "secret-key-123";\n'
        )
        analyzer = WebViewFrameworkAnalyzer()
        strings = analyzer.extract_strings(www)
        assert any("api.example.com" in s for s in strings)
