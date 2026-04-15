import pytest
from pathlib import Path
from chimera.core.cache import AnalysisCache


@pytest.fixture
def cache(tmp_path):
    return AnalysisCache(tmp_path / "cache")


class TestAnalysisCache:
    def test_cache_dir_created(self, cache):
        assert cache.cache_dir.exists()

    def test_has_returns_false_for_missing(self, cache):
        assert cache.has("nonexistent_sha256") is False

    def test_put_and_get(self, cache):
        cache.put("abc123", "decompiled", b"int main() { return 0; }")
        result = cache.get("abc123", "decompiled")
        assert result == b"int main() { return 0; }"

    def test_has_returns_true_after_put(self, cache):
        cache.put("abc123", "decompiled", b"data")
        assert cache.has("abc123") is True

    def test_get_missing_returns_none(self, cache):
        assert cache.get("abc123", "decompiled") is None

    def test_separate_categories(self, cache):
        cache.put("abc123", "ghidra", b"ghidra data")
        cache.put("abc123", "r2", b"r2 data")
        assert cache.get("abc123", "ghidra") == b"ghidra data"
        assert cache.get("abc123", "r2") == b"r2 data"

    def test_put_json(self, cache):
        cache.put_json("abc123", "triage", {"arch": "arm64", "size": 1024})
        result = cache.get_json("abc123", "triage")
        assert result["arch"] == "arm64"
        assert result["size"] == 1024

    def test_get_json_missing_returns_none(self, cache):
        assert cache.get_json("abc123", "triage") is None

    def test_cache_path_for(self, cache):
        path = cache.path_for("abc123", "decompiled")
        assert "abc123" in str(path)
