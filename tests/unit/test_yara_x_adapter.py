"""Tests for the YARA-X adapter and selector."""

from __future__ import annotations

import asyncio
import os

import pytest

from chimera.adapters.yara_adapter import YaraAdapter
from chimera.adapters.yara_x_adapter import YaraXAdapter, select_yara_adapter


def test_yara_x_is_available_reflects_module_presence():
    """We don't pin yara-x in the wheel — adapter must degrade cleanly when missing."""
    adapter = YaraXAdapter()
    # Either present and reports True, or absent and reports False.
    # Either way, `is_available()` must be idempotent and not raise.
    first = adapter.is_available()
    second = adapter.is_available()
    assert first == second


def test_select_yara_adapter_defaults_to_legacy_yara(monkeypatch):
    """Without CHIMERA_USE_YARA_X, legacy YARA stays the default backend."""
    monkeypatch.delenv("CHIMERA_USE_YARA_X", raising=False)
    chosen = select_yara_adapter()
    assert isinstance(chosen, YaraAdapter)
    assert chosen.name() == "yara"


def test_select_yara_adapter_falls_back_when_x_unavailable(monkeypatch):
    """Even when the env var is set, fall back to legacy YARA if yara-x isn't installed."""
    monkeypatch.setenv("CHIMERA_USE_YARA_X", "1")

    # Patch YaraXAdapter so the selector sees it as unavailable.
    from chimera.adapters import yara_x_adapter as yxa

    class _Stub(yxa.YaraXAdapter):
        def is_available(self):
            return False

    monkeypatch.setattr(yxa, "YaraXAdapter", _Stub)
    chosen = yxa.select_yara_adapter()
    assert isinstance(chosen, YaraAdapter)


def test_yara_x_adapter_returns_unavailable_when_module_missing():
    """analyze() on a no-yara-x environment must return the documented shape."""
    adapter = YaraXAdapter()
    if adapter.is_available():
        pytest.skip("yara-x is installed; this test covers the absent path")
    result = asyncio.run(adapter.analyze("/nonexistent", {}))
    assert result == {"available": False, "hits": []}


def test_yara_x_adapter_supports_expected_formats():
    adapter = YaraXAdapter()
    fmts = set(adapter.supported_formats())
    assert {"elf", "macho", "dex", "pe"}.issubset(fmts)
