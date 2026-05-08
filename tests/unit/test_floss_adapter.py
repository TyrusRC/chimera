"""Unit tests for the FLOSS adapter (mocked subprocess)."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chimera.adapters.floss import FlossAdapter, _normalize


def test_floss_supported_formats():
    a = FlossAdapter()
    assert "pe32" in a.supported_formats()
    assert "pe64" in a.supported_formats()
    assert "elf_standalone" in a.supported_formats()


def test_floss_unavailable_returns_empty():
    a = FlossAdapter()
    a._floss_bin = None  # simulate missing binary
    out = asyncio.run(a.analyze("/nonexistent/path", {}))
    assert out["available"] is False
    assert out["decoded"] == []
    assert out["stack"] == []
    assert out["tight"] == []


def test_normalize_full_payload():
    payload = {
        "strings": {
            "static_strings": [],
            "stack_strings": [
                {"string": "secret", "function_address": 0x1000},
            ],
            "tight_strings": [
                {"string": "secret2", "function_address": 0x2000},
            ],
            "decoded_strings": [
                {"string": "C2.example.com", "address": 0x401234, "encoding": "ascii"},
            ],
        },
    }
    out = _normalize(payload)
    assert out["available"] is True
    assert len(out["decoded"]) == 1
    assert out["decoded"][0]["value"] == "C2.example.com"
    assert out["decoded"][0]["address"] == "0x401234"
    assert out["stack"][0]["function"] == "0x1000"
    assert out["tight"][0]["function"] == "0x2000"
    assert out["stats"] == {"decoded_count": 1, "stack_count": 1, "tight_count": 1}


def test_normalize_empty_payload():
    out = _normalize({})
    assert out["decoded"] == []
    assert out["stats"]["decoded_count"] == 0


def test_normalize_drops_strings_without_value():
    payload = {"strings": {"decoded_strings": [{"string": None, "address": 0x1}]}}
    out = _normalize(payload)
    assert out["decoded"] == []


@pytest.mark.asyncio
async def test_analyze_succeeds_with_mocked_subprocess(tmp_path):
    a = FlossAdapter()
    a._floss_bin = "/usr/bin/floss"  # pretend it's available

    canned = {
        "strings": {
            "decoded_strings": [{"string": "hello", "address": 0x100, "encoding": "ascii"}],
            "stack_strings": [],
            "tight_strings": [],
        }
    }
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(json.dumps(canned).encode(), b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = await a.analyze(str(tmp_path / "x.exe"), {})

    assert out["available"] is True
    assert len(out["decoded"]) == 1
    assert out["decoded"][0]["value"] == "hello"


@pytest.mark.asyncio
async def test_analyze_returns_error_on_nonzero_exit(tmp_path):
    a = FlossAdapter()
    a._floss_bin = "/usr/bin/floss"

    proc = MagicMock()
    proc.returncode = 1
    proc.communicate = AsyncMock(return_value=(b"", b"floss: error"))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = await a.analyze(str(tmp_path / "x.exe"), {})

    assert out["available"] is True
    assert out["decoded"] == []
    assert "error" in out
