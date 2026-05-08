"""Unit tests for the Volatility adapter (mocked subprocess)."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chimera.adapters.volatility import VolatilityAdapter, _resolve_vol_binary


def test_supported_formats():
    a = VolatilityAdapter()
    assert "memory_lime" in a.supported_formats()
    assert "memory_raw" in a.supported_formats()


def test_unavailable_returns_empty():
    a = VolatilityAdapter()
    a._vol_bin = None
    out = asyncio.run(a.analyze("/nonexistent", {"plugin": "linux.pslist.PsList"}))
    assert out["available"] is False
    assert out["rows"] == []


def test_missing_plugin_arg_errors_cleanly():
    a = VolatilityAdapter()
    a._vol_bin = "/usr/bin/vol"  # pretend installed
    out = asyncio.run(a.analyze("/some/image.lime", {}))
    assert out["available"] is True
    assert out["rows"] == []
    assert "error" in out


def test_analyze_parses_top_level_array():
    a = VolatilityAdapter()
    a._vol_bin = "/usr/bin/vol"

    canned = [
        {"PID": 1, "PPID": 0, "COMM": "init"},
        {"PID": 2, "PPID": 1, "COMM": "kthreadd"},
    ]
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(json.dumps(canned).encode(), b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze("/x.lime", {"plugin": "linux.pslist.PsList"}))

    assert out["available"] is True
    assert out["plugin"] == "linux.pslist.PsList"
    assert len(out["rows"]) == 2
    assert out["stats"]["row_count"] == 2


def test_analyze_parses_object_with_rows_key():
    a = VolatilityAdapter()
    a._vol_bin = "/usr/bin/vol"

    canned = {"rows": [{"PID": 42}], "schema": ["PID"]}
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(json.dumps(canned).encode(), b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze("/x.lime", {"plugin": "linux.pslist.PsList"}))

    assert len(out["rows"]) == 1
    assert out["rows"][0]["PID"] == 42


def test_analyze_returns_error_on_nonzero_exit():
    a = VolatilityAdapter()
    a._vol_bin = "/usr/bin/vol"

    proc = MagicMock()
    proc.returncode = 1
    proc.communicate = AsyncMock(return_value=(b"", b"vol: symbol table not found"))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze("/x.lime", {"plugin": "linux.pslist.PsList"}))

    assert out["available"] is True
    assert out["rows"] == []
    assert "error" in out


def test_analyze_handles_invalid_json():
    a = VolatilityAdapter()
    a._vol_bin = "/usr/bin/vol"

    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"not json", b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze("/x.lime", {"plugin": "linux.pslist.PsList"}))

    assert out["rows"] == []
    assert "json decode failed" in out["error"]


def test_resolve_vol_binary_returns_none_when_absent():
    with patch("shutil.which", return_value=None):
        assert _resolve_vol_binary() is None


def test_resolve_vol_binary_finds_vol():
    with patch("shutil.which", side_effect=lambda c: "/usr/bin/vol" if c == "vol" else None):
        assert _resolve_vol_binary() == "/usr/bin/vol"
