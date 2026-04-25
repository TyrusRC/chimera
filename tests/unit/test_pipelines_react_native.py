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
