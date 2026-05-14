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


def test_sdk_packages_added_and_removed():
    a = _snap(jadx_packages=["okhttp3", "kotlinx.coroutines.core", "androidx.compose.ui"])
    b = _snap(jadx_packages=["okhttp3", "kotlinx.coroutines.core",
                             "androidx.compose.ui", "com.google.firebase.crashlytics"])
    diff = diff_projects(a, b)
    assert "com.google.firebase.crashlytics" in diff.sdks_added
    assert diff.sdks_removed == []


def test_sdk_packages_no_change():
    a = _snap(jadx_packages=["okhttp3"])
    b = _snap(jadx_packages=["okhttp3"])
    diff = diff_projects(a, b)
    assert diff.sdks_added == []
    assert diff.sdks_removed == []


def test_native_libs_added_and_removed():
    a = _snap(native_libs={
        "libfoo.so": {"sha256": "aaa", "size_bytes": 1024},
        "libstable.so": {"sha256": "bbb", "size_bytes": 2048},
    })
    b = _snap(native_libs={
        "libnew.so": {"sha256": "ccc", "size_bytes": 4096},
        "libstable.so": {"sha256": "bbb", "size_bytes": 2048},  # unchanged
    })
    diff = diff_projects(a, b)
    assert {n.name for n in diff.native_libs_added} == {"libnew.so"}
    assert {n.name for n in diff.native_libs_removed} == {"libfoo.so"}
    assert diff.native_libs_changed == []  # libstable.so unchanged → not flagged


def test_native_libs_changed_when_sha_differs():
    a = _snap(native_libs={
        "libfoo.so": {"sha256": "aaa"},
    })
    b = _snap(native_libs={
        "libfoo.so": {"sha256": "ddd"},
    })
    diff = diff_projects(a, b)
    assert {n.name for n in diff.native_libs_changed} == {"libfoo.so"}
    assert diff.native_libs_added == []
    assert diff.native_libs_removed == []


_MANIFEST_DEBUG_REGRESSION = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <application android:debuggable="true" android:allowBackup="false"
        android:fullBackupContent="@xml/bk">
        <activity android:name=".M" android:exported="false"/>
    </application>
</manifest>
"""


def test_findings_regression_and_resolution():
    # A: clean (no manifest issues); B: introduces MANIFEST-DEBUGGABLE.
    a = _snap(manifest_xml=_MANIFEST_A)
    b = _snap(manifest_xml=_MANIFEST_DEBUG_REGRESSION)
    diff = diff_projects(a, b)
    added_ids = {f.finding_id for f in diff.findings_added}
    assert "MANIFEST-DEBUGGABLE" in added_ids
    # MANIFEST-EXPORTED was in A (.OldActivity exported true, no permission)
    # but resolved in B (only .M activity, exported=false).
    removed_ids = {f.finding_id for f in diff.findings_resolved}
    assert "MANIFEST-EXPORTED" in removed_ids


def test_findings_unchanged_not_listed():
    a = _snap(manifest_xml=_MANIFEST_DEBUG_REGRESSION)
    b = _snap(manifest_xml=_MANIFEST_DEBUG_REGRESSION)
    diff = diff_projects(a, b)
    assert diff.findings_added == []
    assert diff.findings_resolved == []


def test_evidence_key_ignores_manifest_line_number():
    from chimera.diff.engine import _evidence_key
    from chimera.detection_engineering.cvss_findings import Finding

    a = Finding(
        finding_id="MANIFEST-CLEARTEXT",
        title="t",
        severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_base_score=0.0,
        evidence=["AndroidManifest.xml:14 cleartextTraffic=true"],
    )
    b = Finding(
        finding_id="MANIFEST-CLEARTEXT",
        title="t",
        severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_base_score=0.0,
        evidence=["AndroidManifest.xml:27 cleartextTraffic=true"],
    )
    assert _evidence_key(a) == _evidence_key(b)


def test_evidence_key_preserves_distinct_evidence():
    from chimera.diff.engine import _evidence_key
    from chimera.detection_engineering.cvss_findings import Finding

    a = Finding(
        finding_id="MANIFEST-CLEARTEXT",
        title="t",
        severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_base_score=0.0,
        evidence=["AndroidManifest.xml:14 cleartextTraffic=true"],
    )
    b = Finding(
        finding_id="MANIFEST-CLEARTEXT",
        title="t",
        severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_base_score=0.0,
        evidence=["AndroidManifest.xml:14 networkSecurityConfig present"],
    )
    assert _evidence_key(a) != _evidence_key(b)
