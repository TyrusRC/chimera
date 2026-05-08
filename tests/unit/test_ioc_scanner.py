"""Unit tests for the IoC scanner."""
import pytest

from chimera.detection_engineering.ioc_scanner import (
    CONF_HIGH, CONF_MEDIUM, IocMatch, scan_iocs, summarize,
    _is_filtered_ipv4, _is_filtered_domain,
)


def _str(value: str, address: str = "0x1000") -> dict:
    return {"value": value, "address": address}


def test_empty_input_returns_empty():
    assert scan_iocs([]) == []


def test_extracts_https_url():
    out = scan_iocs([_str("config: https://api.evil.example/v1/c2")])
    urls = [m for m in out if m.category == "url"]
    assert len(urls) == 1
    assert urls[0].value.startswith("https://")
    assert urls[0].confidence == CONF_HIGH


def test_filters_localhost_url():
    out = scan_iocs([_str("debug http://localhost:8080/health")])
    urls = [m for m in out if m.category == "url"]
    assert urls == []


def test_extracts_public_ipv4():
    out = scan_iocs([_str("ping 8.8.8.8 for sanity")])
    ipv4 = [m for m in out if m.category == "ipv4"]
    assert any(m.value == "8.8.8.8" for m in ipv4)


def test_filters_loopback_ipv4():
    out = scan_iocs([_str("connect 127.0.0.1:8080")])
    assert [m for m in out if m.category == "ipv4"] == []


def test_filters_private_ipv4():
    out = scan_iocs([_str("connect 192.168.1.1")])
    assert [m for m in out if m.category == "ipv4"] == []


def test_filters_version_number_ipv4():
    out = scan_iocs([_str("version 1.2.3.4 release")])
    assert [m for m in out if m.category == "ipv4"] == []


def test_filters_documentation_range():
    out = scan_iocs([_str("see RFC 5737 example: 192.0.2.1")])
    assert [m for m in out if m.category == "ipv4"] == []


def test_extracts_domain():
    out = scan_iocs([_str("download from cdn.malicious-domain.tld now")])
    domains = [m for m in out if m.category == "domain"]
    assert any(m.value == "cdn.malicious-domain.tld" for m in domains)


def test_filters_java_package_path():
    out = scan_iocs([_str("class java.util.HashMap"),
                     _str("class kotlin.collections.MutableList")])
    domains = [m for m in out if m.category == "domain"]
    assert domains == []


def test_filters_filename_as_domain():
    out = scan_iocs([_str("/lib/libfoo.so"), _str("config.xml")])
    domains = [m for m in out if m.category == "domain"]
    # libfoo.so / config.xml shouldn't be flagged as domains
    assert all("libfoo.so" not in m.value and "config.xml" not in m.value
               for m in domains)


def test_extracts_email():
    out = scan_iocs([_str("contact admin@evil-corp.tld for ransom")])
    emails = [m for m in out if m.category == "email"]
    assert any(m.value == "admin@evil-corp.tld" for m in emails)


def test_extracts_sha256():
    h = "a" * 64
    out = scan_iocs([_str(f"hash: {h}")])
    found = [m for m in out if m.category == "hash_sha256"]
    assert any(m.value == h for m in found)


def test_extracts_sha1():
    h = "b" * 40
    out = scan_iocs([_str(f"sha1: {h}")])
    found = [m for m in out if m.category == "hash_sha1"]
    assert any(m.value == h for m in found)


def test_extracts_md5():
    h = "c" * 32
    out = scan_iocs([_str(f"md5: {h}")])
    found = [m for m in out if m.category == "hash_md5"]
    assert any(m.value == h for m in found)


def test_extracts_btc_address():
    # Real-looking Bitcoin address (Genesis block)
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    out = scan_iocs([_str(f"send btc to {addr} immediately")])
    btc = [m for m in out if m.category == "btc_address"]
    assert any(m.value == addr for m in btc)


def test_extracts_onion_v3():
    # 56-char base32 + .onion
    onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
    out = scan_iocs([_str(f"reach {onion} via tor")])
    onions = [m for m in out if m.category == "onion_v3"]
    assert len(onions) == 1


def test_dedupes_within_run():
    out = scan_iocs([
        _str("see https://api.evil.example/c2"),
        _str("again https://api.evil.example/c2"),
    ])
    urls = [m for m in out if m.category == "url"]
    assert len(urls) == 1


def test_url_host_not_double_counted_as_domain():
    out = scan_iocs([_str("server https://api.evil.tld/v1")])
    cats = [m.category for m in out]
    # Should have one URL match
    assert "url" in cats
    # The host shouldn't ALSO show up as a separate domain match
    domain_matches = [m for m in out if m.category == "domain"
                      and "evil.tld" in m.value]
    assert domain_matches == []


def test_preserves_address():
    out = scan_iocs([_str("https://api.evil.tld", address="0xabcd")])
    assert all(m.source_address == "0xabcd" for m in out)


def test_summarize_returns_counts():
    matches = [
        IocMatch("https://x.tld", "url", CONF_HIGH, "src"),
        IocMatch("https://y.tld", "url", CONF_HIGH, "src"),
        IocMatch("8.8.8.8", "ipv4", CONF_HIGH, "src"),
    ]
    counts = summarize(matches)
    assert counts == {"url": 2, "ipv4": 1}


def test_iocmatch_serializes_to_dict():
    m = IocMatch("https://x", "url", CONF_HIGH, "source string", "0x100")
    d = m.to_dict()
    assert d["value"] == "https://x"
    assert d["category"] == "url"
    assert d["confidence"] == CONF_HIGH
