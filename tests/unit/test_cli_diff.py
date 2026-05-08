from __future__ import annotations
from pathlib import Path

import pytest
from click.testing import CliRunner

from chimera.cli import main
from chimera.core.cache import AnalysisCache


_MANIFEST_A = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:debuggable="false" android:allowBackup="false"
        android:fullBackupContent="@xml/bk"/>
</manifest>
"""

_MANIFEST_B = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <application android:debuggable="false" android:allowBackup="false"
        android:fullBackupContent="@xml/bk"/>
</manifest>
"""


@pytest.fixture
def cache_with_two_projects(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = AnalysisCache(cache_dir)
    sha_a = "a" * 64
    sha_b = "b" * 64
    cache.put(sha_a, "manifest_xml", _MANIFEST_A)
    cache.put(sha_b, "manifest_xml", _MANIFEST_B)
    return cache_dir, sha_a, sha_b


def test_diff_cmd_shows_added_permission_in_markdown(cache_with_two_projects):
    cache_dir, sha_a, sha_b = cache_with_two_projects
    runner = CliRunner()
    result = runner.invoke(main, [
        "diff", sha_a, sha_b, "--cache-dir", str(cache_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "+ android.permission.READ_PHONE_STATE" in result.output


def test_diff_cmd_json_format(cache_with_two_projects):
    import json
    cache_dir, sha_a, sha_b = cache_with_two_projects
    runner = CliRunner()
    result = runner.invoke(main, [
        "diff", sha_a, sha_b, "--cache-dir", str(cache_dir), "--format", "json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "android.permission.READ_PHONE_STATE" in payload["permissions"]["added"]


def test_diff_cmd_missing_project_errors(tmp_path):
    cache_dir = tmp_path / "cache"
    AnalysisCache(cache_dir)  # creates an empty cache
    runner = CliRunner()
    result = runner.invoke(main, [
        "diff", "0" * 64, "1" * 64, "--cache-dir", str(cache_dir),
    ])
    assert result.exit_code != 0
    assert "not in cache" in result.output.lower() or "not found" in result.output.lower()
