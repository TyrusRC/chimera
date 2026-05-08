"""Unit tests for the STIX 2.1 bundle exporter."""
import json
from pathlib import Path

from chimera.detection_engineering.ioc_scanner import IocMatch, CONF_HIGH, CONF_MEDIUM
from chimera.detection_engineering.stix_export import (
    SPEC_VERSION, _pattern_for, build_stix_bundle,
)
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="abc" * 21 + "x", path=Path("/tmp/sample.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_pattern_for_url():
    m = IocMatch("https://evil.tld/c2", "url", CONF_HIGH, "src")
    assert _pattern_for(m) == "[url:value = 'https://evil.tld/c2']"


def test_pattern_for_ipv4():
    m = IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src")
    assert _pattern_for(m) == "[ipv4-addr:value = '8.8.8.8']"


def test_pattern_for_sha256():
    h = "f" * 64
    m = IocMatch(h, "hash_sha256", CONF_MEDIUM, "src")
    assert _pattern_for(m) == f"[file:hashes.'SHA-256' = '{h}']"


def test_pattern_for_onion_treated_as_domain():
    onion = "a" * 56 + ".onion"
    m = IocMatch(onion, "onion_v3", CONF_HIGH, "src")
    assert _pattern_for(m) == f"[domain-name:value = '{onion}']"


def test_pattern_for_btc_address():
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    m = IocMatch(addr, "btc_address", CONF_HIGH, "src")
    assert "x-cryptocurrency-address" in _pattern_for(m)


def test_pattern_escapes_quotes():
    m = IocMatch("https://x.tld/'inj", "url", CONF_HIGH, "src")
    assert "\\'" in _pattern_for(m)


def test_build_bundle_top_level_shape():
    bundle = build_stix_bundle(_model(), [])
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)


def test_bundle_contains_identity_and_malware_analysis():
    bundle = build_stix_bundle(_model(), [])
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" in types
    assert "file" in types
    assert "malware-analysis" in types


def test_bundle_includes_indicator_per_match():
    matches = [
        IocMatch("https://evil.tld/c2", "url", CONF_HIGH, "src"),
        IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src"),
    ]
    bundle = build_stix_bundle(_model(), matches)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    patterns = {i["pattern"] for i in indicators}
    assert "[url:value = 'https://evil.tld/c2']" in patterns
    assert "[ipv4-addr:value = '8.8.8.8']" in patterns


def test_bundle_includes_relationships_for_each_indicator():
    matches = [IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src")]
    bundle = build_stix_bundle(_model(), matches)
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "indicates"


def test_bundle_is_json_serializable():
    bundle = build_stix_bundle(_model(), [
        IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src"),
    ])
    s = json.dumps(bundle)
    assert "bundle" in s


def test_bundle_skips_unsupported_categories():
    matches = [
        IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src"),
        IocMatch("???", "unknown_category", CONF_HIGH, "src"),
    ]
    bundle = build_stix_bundle(_model(), matches)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1


def test_confidence_mapped_to_numeric():
    bundle = build_stix_bundle(_model(), [
        IocMatch("8.8.8.8", "ipv4", "high", "src"),
        IocMatch("1.1.1.1", "ipv4", "medium", "src"),
    ])
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    confs = sorted(i["confidence"] for i in indicators)
    assert confs == [60, 90]
