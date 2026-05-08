"""Unit tests for the bundled Frida script registry."""
import pytest

from chimera.frida_scripts import (
    ScriptMeta, _parse_header, get_script, list_scripts, read_source,
)


def test_list_scripts_returns_at_least_5():
    out = list_scripts()
    assert len(out) >= 5


def test_each_script_has_required_metadata():
    for s in list_scripts():
        assert s.id
        assert s.name
        assert s.platform in {"android", "ios", "both"}
        assert s.risk in {"low", "medium", "high"}
        assert s.file.exists()


def test_get_script_returns_known_script():
    s = get_script("android-ssl-pinning-bypass")
    assert s is not None
    assert s.platform == "android"
    assert "pinning" in s.name.lower()


def test_get_script_unknown_returns_none():
    assert get_script("definitely-not-a-real-script") is None


def test_read_source_returns_js_text():
    src = read_source("android-ssl-pinning-bypass")
    assert src is not None
    assert "Java.perform" in src or "ObjC" in src


def test_read_source_unknown_returns_none():
    assert read_source("nope") is None


def test_parse_header_rejects_files_without_marker(tmp_path):
    f = tmp_path / "x.js"
    f.write_text("// just a regular script\nconsole.log('hi');")
    assert _parse_header(f.read_text(), f) is None


def test_parse_header_extracts_metadata(tmp_path):
    f = tmp_path / "x.js"
    f.write_text(
        "// chimera-frida-script\n"
        "// id: test-x\n"
        "// name: Test X\n"
        "// description: A test\n"
        "// platform: android\n"
        "// requires: Java, OkHttp\n"
        "// risk: low\n"
        "Java.perform(function(){});\n"
    )
    meta = _parse_header(f.read_text(), f)
    assert meta is not None
    assert meta.id == "test-x"
    assert meta.platform == "android"
    assert meta.requires == ["Java", "OkHttp"]
    assert meta.risk == "low"


def test_script_meta_serializes_to_dict():
    s = list_scripts()[0]
    d = s.to_dict()
    assert "id" in d and "name" in d and "platform" in d


def test_all_5_canonical_scripts_present():
    ids = {s.id for s in list_scripts()}
    expected = {
        "android-ssl-pinning-bypass",
        "ios-ssl-pinning-bypass",
        "android-root-detection-bypass",
        "ios-jailbreak-detection-bypass",
        "android-keystore-dump",
    }
    assert expected.issubset(ids)


def test_platform_partition():
    out = list_scripts()
    android = [s for s in out if s.platform in ("android", "both")]
    ios = [s for s in out if s.platform in ("ios", "both")]
    assert len(android) >= 3
    assert len(ios) >= 2
