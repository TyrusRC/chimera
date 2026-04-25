"""Unit tests for the React Native sub-pipeline."""

from __future__ import annotations

from pathlib import Path

from chimera.pipelines.react_native import (
    find_rn_bundle,
    find_source_map,
)


class TestFindRnBundle:
    def test_android_index_android_bundle(self, tmp_path: Path):
        (tmp_path / "assets").mkdir()
        bundle = tmp_path / "assets" / "index.android.bundle"
        bundle.write_bytes(b"// JS bundle")
        assert find_rn_bundle(tmp_path, "android") == bundle

    def test_android_index_bundle_fallback(self, tmp_path: Path):
        (tmp_path / "assets").mkdir()
        bundle = tmp_path / "assets" / "index.bundle"
        bundle.write_bytes(b"// JS bundle")
        assert find_rn_bundle(tmp_path, "android") == bundle

    def test_android_priority_index_android_over_index(self, tmp_path: Path):
        (tmp_path / "assets").mkdir()
        primary = tmp_path / "assets" / "index.android.bundle"
        primary.write_bytes(b"primary")
        (tmp_path / "assets" / "index.bundle").write_bytes(b"fallback")
        assert find_rn_bundle(tmp_path, "android") == primary

    def test_android_no_bundle_returns_none(self, tmp_path: Path):
        (tmp_path / "assets").mkdir()
        assert find_rn_bundle(tmp_path, "android") is None

    def test_ios_main_jsbundle(self, tmp_path: Path):
        bundle = tmp_path / "main.jsbundle"
        bundle.write_bytes(b"// JS bundle")
        assert find_rn_bundle(tmp_path, "ios") == bundle

    def test_ios_arbitrary_jsbundle(self, tmp_path: Path):
        bundle = tmp_path / "app.jsbundle"
        bundle.write_bytes(b"// JS bundle")
        assert find_rn_bundle(tmp_path, "ios") == bundle

    def test_ios_no_bundle_returns_none(self, tmp_path: Path):
        assert find_rn_bundle(tmp_path, "ios") is None

    def test_android_directory_named_like_bundle_is_skipped(self, tmp_path: Path):
        (tmp_path / "assets" / "index.android.bundle").mkdir(parents=True)
        assert find_rn_bundle(tmp_path, "android") is None

    def test_ios_directory_named_like_bundle_is_skipped(self, tmp_path: Path):
        (tmp_path / "main.jsbundle").mkdir()
        assert find_rn_bundle(tmp_path, "ios") is None


class TestFindSourceMap:
    def test_sibling_dot_map_suffix(self, tmp_path: Path):
        bundle = tmp_path / "index.android.bundle"
        bundle.write_bytes(b"x")
        smap = tmp_path / "index.android.bundle.map"
        smap.write_text("{}")
        assert find_source_map(bundle) == smap

    def test_sibling_stem_map(self, tmp_path: Path):
        bundle = tmp_path / "main.jsbundle"
        bundle.write_bytes(b"x")
        smap = tmp_path / "main.map"
        smap.write_text("{}")
        assert find_source_map(bundle) == smap

    def test_priority_full_suffix_wins(self, tmp_path: Path):
        bundle = tmp_path / "main.jsbundle"
        bundle.write_bytes(b"x")
        primary = tmp_path / "main.jsbundle.map"
        primary.write_text("primary")
        (tmp_path / "main.map").write_text("fallback")
        assert find_source_map(bundle) == primary

    def test_no_map_returns_none(self, tmp_path: Path):
        bundle = tmp_path / "main.jsbundle"
        bundle.write_bytes(b"x")
        assert find_source_map(bundle) is None

    def test_directory_named_like_map_is_skipped(self, tmp_path: Path):
        bundle = tmp_path / "main.jsbundle"
        bundle.write_bytes(b"x")
        (tmp_path / "main.jsbundle.map").mkdir()
        assert find_source_map(bundle) is None


import json

from chimera.model.binary import BinaryInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.react_native import (
    parse_source_map,
    populate_model_from_sourcemap,
)


def _fake_binary(tmp_path: Path) -> BinaryInfo:
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    return BinaryInfo.from_path(apk)


class TestParseSourceMap:
    def test_minimal_valid_map(self, tmp_path: Path):
        smap = tmp_path / "x.map"
        smap.write_text(json.dumps({
            "version": 3,
            "sources": ["src/A.js", "src/B.js"],
            "sourcesContent": ["const a = 1;", "const b = 2;"],
            "mappings": "AAAA",
            "names": ["a", "b"],
        }))
        result = parse_source_map(smap)
        assert result is not None
        assert result["version"] == 3
        assert result["sources"] == ["src/A.js", "src/B.js"]
        assert result["sourcesContent"] == ["const a = 1;", "const b = 2;"]
        assert result["mappings"] == "AAAA"

    def test_missing_sources_content_tolerated(self, tmp_path: Path):
        smap = tmp_path / "x.map"
        smap.write_text(json.dumps({
            "version": 3,
            "sources": ["src/A.js"],
            "mappings": "",
        }))
        result = parse_source_map(smap)
        assert result is not None
        assert result["sourcesContent"] == []

    def test_malformed_json_returns_none(self, tmp_path: Path):
        smap = tmp_path / "x.map"
        smap.write_text("{not json")
        assert parse_source_map(smap) is None

    def test_missing_file_returns_none(self, tmp_path: Path):
        assert parse_source_map(tmp_path / "missing.map") is None


class TestPopulateModelFromSourcemap:
    def test_function_per_source_with_original_name(self, tmp_path: Path):
        model = UnifiedProgramModel(_fake_binary(tmp_path))
        sm = {
            "version": 3,
            "sources": ["src/screens/Login.js", "src/utils/api.js"],
            "sourcesContent": ["// login", "// api"],
            "mappings": "",
            "names": [],
        }
        count = populate_model_from_sourcemap(model, sm)
        assert count == 2
        funcs = {f.address: f for f in model.functions}
        assert "rn_module_0" in funcs
        assert funcs["rn_module_0"].original_name == "src/screens/Login.js"
        assert funcs["rn_module_0"].name == "Login"
        assert funcs["rn_module_0"].language == "javascript"
        assert funcs["rn_module_0"].layer == "bundle"
        assert funcs["rn_module_0"].source_backend == "react_native"

    def test_interesting_strings_extracted_from_sources_content(self, tmp_path: Path):
        model = UnifiedProgramModel(_fake_binary(tmp_path))
        sm = {
            "version": 3,
            "sources": ["src/api.js"],
            "sourcesContent": [
                "const URL = 'https://api.example.com/v1/users';\nconst x = 1;"
            ],
            "mappings": "",
            "names": [],
        }
        populate_model_from_sourcemap(model, sm)
        urls = [s.value for s in model.get_strings() if "example.com" in s.value]
        assert urls, "expected URL pulled from sourcesContent"

    def test_handles_missing_sources_content_entry(self, tmp_path: Path):
        model = UnifiedProgramModel(_fake_binary(tmp_path))
        sm = {
            "version": 3,
            "sources": ["src/A.js", "src/B.js"],
            "sourcesContent": ["// a only"],  # shorter than sources
            "mappings": "",
            "names": [],
        }
        # Must not raise.
        count = populate_model_from_sourcemap(model, sm)
        assert count == 2
