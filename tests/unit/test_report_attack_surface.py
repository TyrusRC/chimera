"""Report attack_surface block lists format-appropriate entry points."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import ImportEntry
from chimera.model.program import UnifiedProgramModel
from chimera.report.builder import build_report


def _pe_model_with_imports() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="a" * 64, path=Path("/x"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    m.add_import(ImportEntry(dll="kernel32.dll", name="CreateFileW", address="0x401000", bucket="file"))
    m.add_import(ImportEntry(dll="ws2_32.dll", name="connect", address="0x401004", bucket="network"))
    m.add_import(ImportEntry(dll="kernel32.dll", name="ReadFile", address="0x401008", bucket="file"))
    return m


def test_attack_surface_pe_lists_imports_by_bucket():
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.return_value = None
    r = build_report(_pe_model_with_imports(), cache)
    surf = r["attack_surface"]
    assert "imports_by_bucket" in surf
    by_bucket = surf["imports_by_bucket"]
    assert "file" in by_bucket
    assert "network" in by_bucket
    assert "kernel32.dll!CreateFileW" in by_bucket["file"]
    assert "kernel32.dll!ReadFile" in by_bucket["file"]
    assert "ws2_32.dll!connect" in by_bucket["network"]


def test_attack_surface_android_lists_exported_components():
    bi = BinaryInfo(
        sha256="a" * 64, path=Path("/x.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.side_effect = lambda sha, key: {
        "manifest_components": [
            {"kind": "activity", "name": ".LoginActivity", "exported": True, "has_intent_filter": True},
            {"kind": "service", "name": ".SyncService", "exported": False, "has_intent_filter": False},
            {"kind": "receiver", "name": ".BootReceiver", "exported": True, "has_intent_filter": True},
        ],
    }.get(key)
    r = build_report(m, cache)
    surf = r["attack_surface"]
    assert "exported_components" in surf
    names = {c["name"] for c in surf["exported_components"]}
    assert ".LoginActivity" in names
    assert ".BootReceiver" in names
    assert ".SyncService" not in names


def test_attack_surface_format_field_present():
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.return_value = None
    r = build_report(_pe_model_with_imports(), cache)
    assert r["attack_surface"]["format"] == "pe64"


def test_attack_surface_url_schemes_when_cached():
    bi = BinaryInfo(
        sha256="i" * 64, path=Path("/x.ipa"),
        format=BinaryFormat.IPA, platform=Platform.IOS,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.side_effect = lambda sha, key: {
        "url_schemes": ["myapp", "myapp-debug"],
    }.get(key)
    r = build_report(m, cache)
    assert r["attack_surface"]["url_schemes"] == ["myapp", "myapp-debug"]
