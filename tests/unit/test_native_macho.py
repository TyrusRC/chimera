"""Tests for native-Mach-O runtime fingerprinting (frameworks/native_macho.py)."""
from __future__ import annotations

from chimera.frameworks.native_macho import _detect_crystal, detect_macho_runtime


def test_detect_crystal_via_execution_context():
    data = b"....Fiber::ExecutionContext::ThreadPool....more runtime types"
    assert _detect_crystal(data) == ("crystal", "Crystal-lang")


def test_detect_crystal_via_crystal_main():
    assert _detect_crystal(b"\x00__crystal_main\x00")[0] == "crystal"


def test_detect_crystal_with_version():
    assert _detect_crystal(b"Fiber::ExecutionContext Crystal 1.14.0 built")[1] == "Crystal (1.14.0)"


def test_detect_crystal_negative():
    assert detect_macho_runtime(b"a plain C++ Mach-O with no crystal markers") is None
