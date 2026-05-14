"""The report's behavior section aggregates anti-X flags, IOCs, network policy,
and persistence indicators into a single block."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel
from chimera.report.builder import build_report


def _model(fmt: BinaryFormat = BinaryFormat.PE64, plat: Platform = Platform.WINDOWS) -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="b" * 64, path=Path("/x"),
        format=fmt, platform=plat,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_behavior_section_present_with_default_subkeys():
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.return_value = None
    r = build_report(_model(), cache)
    assert "behavior" in r
    b = r["behavior"]
    for key in ("anti_analysis", "network", "persistence", "iocs", "packer"):
        assert key in b, f"missing behavior.{key}"


def test_behavior_anti_analysis_pulls_from_native_protection():
    cache = MagicMock()
    cache.list_keys.return_value = ["native_protection"]
    cache.get_json.side_effect = lambda sha, key: {
        "native_protection": {
            "has_anti_debug": True,
            "has_anti_vm": False,
            "has_self_inject": True,
            "has_persistence_strings": True,
            "anti_debug_evidence": ["IsDebuggerPresent"],
        }
    }.get(key)
    r = build_report(_model(), cache)
    aa = r["behavior"]["anti_analysis"]
    assert aa["anti_debug"] is True
    assert aa["anti_vm"] is False
    assert aa["self_inject"] is True
    assert "IsDebuggerPresent" in (aa.get("evidence") or [])
    assert r["behavior"]["persistence"]["indicators_present"] is True


def test_behavior_network_pulls_from_protection_profile():
    cache = MagicMock()
    cache.list_keys.return_value = ["protection_profile"]
    cache.get_json.side_effect = lambda sha, key: {
        "protection_profile": {
            "cleartext_traffic": True,
            "user_ca_trusted": True,
            "pinning_present": False,
            "anti_frida": True,
            "root_detect": True,
        }
    }.get(key)
    r = build_report(_model(BinaryFormat.APK, Platform.ANDROID), cache)
    net = r["behavior"]["network"]
    assert net["cleartext_permitted"] is True
    assert net["user_ca_trusted"] is True
    assert net["pinning_present"] is False
    aa = r["behavior"]["anti_analysis"]
    assert aa["anti_frida"] is True
    assert aa["root_jailbreak_detect"] is True


def test_behavior_iocs_pulled_when_present():
    cache = MagicMock()
    cache.list_keys.return_value = ["iocs"]
    cache.get_json.side_effect = lambda sha, key: {
        "iocs": {"url": ["http://evil.example/c2"], "ipv4": ["1.2.3.4"]}
    }.get(key)
    r = build_report(_model(), cache)
    assert r["behavior"]["iocs"] == {"url": ["http://evil.example/c2"], "ipv4": ["1.2.3.4"]}
