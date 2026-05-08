from __future__ import annotations

from chimera.diff.loader import ProjectSnapshot
from chimera.diff.engine import diff_projects, ProjectDiff


def _snap(sha="a" * 64, manifest_xml=None, jadx_packages=None, native_libs=None,
          nsc_xml=None):
    return ProjectSnapshot(
        sha256=sha,
        manifest_xml=manifest_xml,
        nsc_xml=nsc_xml,
        jadx_packages=jadx_packages or [],
        native_libs=native_libs or {},
    )


_MANIFEST_A = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <application android:debuggable="false">
        <activity android:name=".OldActivity" android:exported="true"/>
    </application>
</manifest>
"""

_MANIFEST_B = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <application android:debuggable="false">
        <activity android:name=".NewActivity" android:exported="true"/>
    </application>
</manifest>
"""


def test_permissions_added_and_removed():
    a = _snap(sha="a" * 64, manifest_xml=_MANIFEST_A)
    b = _snap(sha="b" * 64, manifest_xml=_MANIFEST_B)

    diff = diff_projects(a, b)

    assert isinstance(diff, ProjectDiff)
    assert "android.permission.READ_PHONE_STATE" in diff.permissions_added
    assert "android.permission.ACCESS_COARSE_LOCATION" in diff.permissions_removed
    # INTERNET is in both → no churn
    assert "android.permission.INTERNET" not in diff.permissions_added
    assert "android.permission.INTERNET" not in diff.permissions_removed


def test_exported_components_added_and_removed():
    a = _snap(manifest_xml=_MANIFEST_A)
    b = _snap(manifest_xml=_MANIFEST_B)

    diff = diff_projects(a, b)

    added = {(c.kind, c.name) for c in diff.exported_added}
    removed = {(c.kind, c.name) for c in diff.exported_removed}
    assert ("activity", ".NewActivity") in added
    assert ("activity", ".OldActivity") in removed


def test_no_manifest_yields_empty_manifest_diff():
    a = _snap()
    b = _snap()
    diff = diff_projects(a, b)
    assert diff.permissions_added == []
    assert diff.permissions_removed == []
    assert diff.exported_added == []
    assert diff.exported_removed == []
