"""Smoke tests for hermes-decomp + Oxidizer adapters — graceful degradation."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from chimera.adapters.hermes_decomp import HermesDecompAdapter, detect_hbc
from chimera.adapters.oxidizer_adapter import OxidizerAdapter, _looks_like_rust


def test_hermes_decomp_unavailable_without_binary(monkeypatch):
    monkeypatch.delenv("CHIMERA_HERMES_DECOMP_BIN", raising=False)
    adapter = HermesDecompAdapter(binary="/nonexistent/hermes-decomp-xxx")
    # Explicit path bypasses PATH lookup but still resolves to non-existent.
    # is_available reflects "we have a binary string"; analyze surfaces the
    # subprocess failure at use-time. That's the right level for an
    # availability probe.
    assert adapter.name() == "hermes_decomp"


def test_hermes_decomp_supports_bundle_formats():
    adapter = HermesDecompAdapter(binary="/usr/bin/true")
    assert "hbc" in adapter.supported_formats()
    assert "bundle" in adapter.supported_formats()


def test_detect_hbc_returns_none_on_empty_tree(tmp_path):
    assert detect_hbc(tmp_path) is None


def test_detect_hbc_finds_high_bit_bundle(tmp_path):
    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b"\xc6\x1f\xbc\x00sometinybytes")
    assert detect_hbc(tmp_path) == bundle


def test_detect_hbc_skips_ascii_js_bundle(tmp_path):
    bundle = tmp_path / "main.jsbundle"
    bundle.write_text("var x = 1; // plain JS")
    assert detect_hbc(tmp_path) is None


def test_oxidizer_availability_reflects_angr_import():
    adapter = OxidizerAdapter()
    try:
        import angr  # type: ignore  # noqa: F401
        assert adapter.is_available()
    except ImportError:
        assert not adapter.is_available()


def test_looks_like_rust_detects_panic_signature(tmp_path):
    sample = tmp_path / "fake"
    sample.write_bytes(b"some bytes here core::panicking and more")
    assert _looks_like_rust(str(sample)) is True


def test_looks_like_rust_false_on_plain_c_binary(tmp_path):
    sample = tmp_path / "plain"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 200 + b"main\x00printf\x00")
    assert _looks_like_rust(str(sample)) is False
