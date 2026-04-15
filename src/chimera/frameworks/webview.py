"""Cordova/Ionic/Capacitor analyzer — WebView-based app analysis."""

from __future__ import annotations

import re
from pathlib import Path


class WebViewFrameworkAnalyzer:
    def find_web_assets(self, unpack_dir: Path) -> dict:
        """Find the web assets root directory."""
        unpack_dir = Path(unpack_dir)
        candidates = [
            unpack_dir / "assets" / "www",       # Cordova/Ionic
            unpack_dir / "assets" / "public",    # Capacitor
            unpack_dir / "www",                  # iOS Cordova
        ]
        for root in candidates:
            if root.exists() and (root / "index.html").exists():
                js_files = list(root.rglob("*.js"))
                html_files = list(root.rglob("*.html"))
                css_files = list(root.rglob("*.css"))
                return {
                    "root": root,
                    "js_file_count": len(js_files),
                    "html_file_count": len(html_files),
                    "css_file_count": len(css_files),
                    "total_size": sum(f.stat().st_size for f in js_files),
                }
        return {"root": None, "js_file_count": 0, "html_file_count": 0,
                "css_file_count": 0, "total_size": 0}

    def find_source_maps(self, web_root: Path) -> list[Path]:
        """Find .map source map files (accidental inclusion = full source recovery)."""
        return sorted(Path(web_root).rglob("*.map"))

    def extract_strings(self, web_root: Path) -> list[str]:
        """Extract interesting strings from JS files."""
        strings = []
        patterns = [
            r"https?://[^\s'\"]+",
            r"['\"](?:api|API)[_-]?(?:key|KEY|secret|SECRET|token|TOKEN)['\"]",
            r"['\"]Bearer\s+[^'\"]+['\"]",
            r"localStorage\.(?:setItem|getItem)\s*\(['\"][^'\"]+['\"]",
        ]
        for js_file in Path(web_root).rglob("*.js"):
            try:
                content = js_file.read_text(errors="replace")
                for pat in patterns:
                    strings.extend(re.findall(pat, content))
            except OSError:
                continue
        return list(set(strings))[:500]

    def check_source_map_exposure(self, web_root: Path) -> list[dict]:
        """Check for accidentally included source maps — full source recovery."""
        findings = []
        for map_file in self.find_source_maps(web_root):
            findings.append({
                "rule_id": "DATA-001",
                "title": f"Source map exposed: {map_file.name}",
                "severity": "high",
                "location": str(map_file),
                "description": (
                    f"Source map '{map_file.name}' is included in the app bundle. "
                    "This exposes the complete original source code."
                ),
            })
        return findings
