"""Unit tests for capa adapter — output normalization + graceful skip."""

from __future__ import annotations

import pytest

from chimera.adapters.capa_adapter import CapaAdapter, _normalize_capa_output


def test_unavailable_when_capa_binary_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    adapter = CapaAdapter()
    assert not adapter.is_available()


def test_normalize_capa_output_extracts_rules():
    payload = {
        "rules": {
            "encrypt data using AES": {
                "meta": {
                    "namespace": "data-manipulation/encryption/aes",
                    "lib": False,
                    "attack": [{"technique": "Encrypt Channel"}],
                    "scopes": {"static": "function"},
                },
                "matches": {"0x1234": {}, "0x5678": {}},
            },
            "library: openssl": {
                "meta": {
                    "namespace": "library/openssl",
                    "lib": True,
                    "scopes": {"static": "file"},
                },
                "matches": {"0xa00": {}},
            },
        }
    }
    out = _normalize_capa_output(payload)
    assert out["available"] is True
    rules = {c["rule"]: c for c in out["capabilities"]}
    aes = rules["encrypt data using AES"]
    assert aes["is_library"] is False
    assert aes["address_count"] == 2
    assert "Encrypt Channel" in aes["attack"]
    lib = rules["library: openssl"]
    assert lib["is_library"] is True


def test_normalize_handles_empty_payload():
    out = _normalize_capa_output({})
    assert out == {"available": True, "capabilities": []}


def test_normalize_handles_list_matches():
    payload = {"rules": {"r1": {"meta": {"namespace": ""},
                                 "matches": [["0xabc", {}]]}}}
    out = _normalize_capa_output(payload)
    assert out["capabilities"][0]["address_count"] == 1


@pytest.mark.asyncio
async def test_analyze_returns_unavailable_when_capa_missing(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    adapter = CapaAdapter()
    binary = tmp_path / "libfoo.so"
    binary.write_bytes(b"\x7fELF")
    result = await adapter.analyze(str(binary), {})
    assert result == {"available": False, "capabilities": []}
