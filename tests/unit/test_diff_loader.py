from __future__ import annotations
from pathlib import Path

import pytest

from chimera.diff.loader import load_project, ProjectSnapshot, ProjectNotInCacheError
from chimera.core.cache import AnalysisCache


@pytest.fixture
def cache(tmp_path):
    return AnalysisCache(tmp_path / "cache")


def test_load_by_full_sha256(cache):
    sha = "a" * 64
    cache.put(sha, "manifest_xml", b"<manifest package='com.x'/>")
    cache.put_json(sha, "jadx", {"decompiled_files": 10, "packages": ["okhttp3"], "sources_dir": "/x"})

    snap = load_project(sha, cache)

    assert isinstance(snap, ProjectSnapshot)
    assert snap.sha256 == sha
    assert snap.manifest_xml == b"<manifest package='com.x'/>"
    assert snap.jadx_packages == ["okhttp3"]


def test_load_by_prefix(cache):
    sha = "f" * 64
    cache.put(sha, "manifest_xml", b"<m/>")

    snap = load_project(sha[:12], cache)
    assert snap.sha256 == sha


def test_ambiguous_prefix_raises(cache):
    cache.put("a" * 64, "manifest_xml", b"<m/>")
    cache.put("ab" + "0" * 62, "manifest_xml", b"<m/>")

    with pytest.raises(ValueError, match="ambiguous"):
        load_project("a", cache)


def test_missing_raises(cache):
    with pytest.raises(ProjectNotInCacheError):
        load_project("0" * 64, cache)


def test_load_loads_native_lib_keys(cache):
    sha = "c" * 64
    cache.put(sha, "manifest_xml", b"<m/>")
    cache.put_json(sha, "r2_libfoo.so", {"sha256": "deadbeef", "is_pie": True})
    cache.put_json(sha, "r2_libbar.so", {"sha256": "cafefood", "is_pie": False})

    snap = load_project(sha, cache)

    # Native libraries: name → triage dict
    assert set(snap.native_libs.keys()) == {"libfoo.so", "libbar.so"}
    assert snap.native_libs["libfoo.so"]["sha256"] == "deadbeef"
