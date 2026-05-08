from __future__ import annotations

from chimera.diff.engine import NativeLibChange, ProjectDiff
from chimera.diff.render import render_json, render_markdown
from chimera.detection_engineering.cvss_findings import Finding
from chimera.parsers.android_manifest import ManifestComponent


def _stub_finding(rule="MANIFEST-DEBUGGABLE", line=5):
    return Finding(
        finding_id=rule,
        title="Application is debuggable in production",
        severity="High",
        cvss_vector="CVSS:3.1/...",
        cvss_base_score=7.1,
        masvs_id="MASVS-RESILIENCE",
        cwe_id="CWE-489",
        description="...",
        evidence=[f"AndroidManifest.xml:{line} android:debuggable=\"true\""],
        recommendation="...",
    )


def _stub_component(kind="activity", name=".X", line=8):
    return ManifestComponent(
        kind=kind, name=name, exported=True, has_intent_filter=False,
        permission=None, line=line,
    )


def _full_diff():
    return ProjectDiff(
        a_sha256="a" * 64, b_sha256="b" * 64,
        permissions_added=["android.permission.READ_PHONE_STATE"],
        permissions_removed=["android.permission.ACCESS_COARSE_LOCATION"],
        exported_added=[_stub_component(name=".New")],
        exported_removed=[_stub_component(name=".Old")],
        sdks_added=["com.google.firebase.crashlytics"],
        sdks_removed=[],
        native_libs_added=[NativeLibChange(name="libnew.so", b_sha256="ccc")],
        native_libs_removed=[NativeLibChange(name="libold.so", a_sha256="aaa")],
        native_libs_changed=[NativeLibChange(name="libstable.so",
                                             a_sha256="bbb", b_sha256="bbd")],
        findings_added=[_stub_finding()],
        findings_resolved=[_stub_finding(rule="MANIFEST-BACKUP", line=6)],
    )


def test_render_markdown_includes_all_sections():
    md = render_markdown(_full_diff())
    assert "# chimera diff" in md
    assert "## Permissions" in md
    assert "+ android.permission.READ_PHONE_STATE" in md
    assert "- android.permission.ACCESS_COARSE_LOCATION" in md
    assert "## Exported components" in md
    assert ".New" in md
    assert "## SDKs" in md
    assert "com.google.firebase.crashlytics" in md
    assert "## Native libraries" in md
    assert "libnew.so" in md
    assert "libstable.so" in md
    assert "## Findings" in md
    assert "MANIFEST-DEBUGGABLE" in md
    assert "MANIFEST-BACKUP" in md


def test_render_markdown_skips_empty_sections():
    diff = ProjectDiff(a_sha256="a" * 64, b_sha256="b" * 64)
    md = render_markdown(diff)
    assert md.startswith("# chimera diff")
    assert "## Permissions" not in md
    assert "no differences" in md.lower()


def test_render_json_round_trip():
    diff = _full_diff()
    payload = render_json(diff)
    assert payload["a_sha256"] == "a" * 64
    assert payload["b_sha256"] == "b" * 64
    assert payload["permissions"]["added"] == ["android.permission.READ_PHONE_STATE"]
    assert payload["permissions"]["removed"] == ["android.permission.ACCESS_COARSE_LOCATION"]
    assert payload["sdks"]["added"] == ["com.google.firebase.crashlytics"]
    assert payload["native_libs"]["added"][0]["name"] == "libnew.so"
    assert payload["native_libs"]["changed"][0]["a_sha256"] == "bbb"
    assert payload["findings"]["added"][0]["finding_id"] == "MANIFEST-DEBUGGABLE"
    assert payload["findings"]["resolved"][0]["finding_id"] == "MANIFEST-BACKUP"
