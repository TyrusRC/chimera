"""Unit tests for the MASVS coverage matrix builder."""
from pathlib import Path

import pytest

from chimera.detection_engineering.masvs import (
    STATUS_ANALYST, STATUS_COVERED, STATUS_PARTIAL, STATUS_NA,
    build_masvs_matrix,
)
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel


class _StubCache:
    def __init__(self, blobs: dict | None = None):
        self.cache_dir = Path("/tmp/no-such-cache")
        self._blobs = blobs or {}

    def get_json(self, sha, key):
        return self._blobs.get(key)

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _mobile_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="m" * 64, path=Path("/tmp/x.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def _pe_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="p" * 64, path=Path("/tmp/x.exe"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_pe_returns_not_applicable():
    m = _pe_model()
    out = build_masvs_matrix(m, _StubCache())
    assert out["applicable"] is False
    assert "non-mobile" in out["reason"]


def test_mobile_clean_binary_yields_all_analyst_required():
    m = _mobile_model()
    out = build_masvs_matrix(m, _StubCache())
    assert out["applicable"] is True
    statuses = {row["control_id"]: row["status"] for row in out["rows"]}
    # Without any cache hints, everything defaults to analyst_required
    assert statuses["MASVS-STORAGE"] == STATUS_ANALYST
    assert statuses["MASVS-CRYPTO"] == STATUS_ANALYST
    assert statuses["MASVS-RESILIENCE"] == STATUS_ANALYST
    assert statuses["MASVS-PRIVACY"] == STATUS_ANALYST


def test_crypto_yara_hit_promotes_to_partial():
    m = _mobile_model()
    cache = _StubCache({
        "yara_libnative.so": {
            "yara_hits": [{"rule": "AES_Constants", "meta": {"kind": "crypto_constant"}}],
        },
    })
    out = build_masvs_matrix(m, cache)
    crypto = next(r for r in out["rows"] if r["control_id"] == "MASVS-CRYPTO")
    assert crypto["status"] == STATUS_PARTIAL
    assert "AES_Constants" in crypto["notes"]


def test_resilience_two_signals_yields_covered():
    m = _mobile_model()
    cache = _StubCache({
        "protection_profile": {
            "root_detection": True,
            "anti_debug": True,
        },
    })
    out = build_masvs_matrix(m, cache)
    res = next(r for r in out["rows"] if r["control_id"] == "MASVS-RESILIENCE")
    assert res["status"] == STATUS_COVERED


def test_resilience_one_signal_yields_partial():
    m = _mobile_model()
    cache = _StubCache({
        "protection_profile": {
            "root_detection": True,
        },
    })
    out = build_masvs_matrix(m, cache)
    res = next(r for r in out["rows"] if r["control_id"] == "MASVS-RESILIENCE")
    assert res["status"] == STATUS_PARTIAL


def test_privacy_with_analytics_sdk_yields_partial():
    m = _mobile_model()
    cache = _StubCache({
        "sdks": {
            "matches": [
                {"name": "Google Analytics", "category": "analytics"},
            ],
        },
    })
    out = build_masvs_matrix(m, cache)
    privacy = next(r for r in out["rows"] if r["control_id"] == "MASVS-PRIVACY")
    assert privacy["status"] == STATUS_PARTIAL
    assert "analytics" in privacy["notes"]


def test_network_with_ssl_pinning_yields_partial():
    m = _mobile_model()
    cache = _StubCache({
        "protection_profile": {"ssl_pinning": True},
    })
    out = build_masvs_matrix(m, cache)
    net = next(r for r in out["rows"] if r["control_id"] == "MASVS-NETWORK")
    assert net["status"] == STATUS_PARTIAL


def test_all_8_categories_present():
    m = _mobile_model()
    out = build_masvs_matrix(m, _StubCache())
    ids = {row["control_id"] for row in out["rows"]}
    assert ids == {
        "MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
        "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY",
    }
