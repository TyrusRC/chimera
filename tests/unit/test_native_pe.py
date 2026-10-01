"""Tests for native-PE runtime fingerprinting (frameworks/native_pe.py)."""
from __future__ import annotations

from chimera.frameworks.native_pe import _detect_rust, detect_native_runtime


def test_detect_rust_via_rustc_path():
    data = b"....thread panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/x.rs"
    assert _detect_rust(data) == ("rust", "Rust (rustc/cargo)")


def test_detect_rust_via_cargo_registry():
    assert _detect_rust(b"C:\\Users\\flare\\.cargo\\registry\\src\\index.crates.io-1\\ureq-2")[0] == "rust"


def test_detect_rust_negative():
    assert _detect_rust(b"just some plain C program strings here") is None


def test_dispatch_prefers_go_over_rust_when_both():
    # Go marker wins (checked first); a Rust-only binary is tagged rust.
    assert detect_native_runtime(b"\xff Go buildinf:go1.22.2", [])[0] == "go"
    assert detect_native_runtime(b"/rustc/0123456789abcdef0/library/", [])[0] == "rust"
