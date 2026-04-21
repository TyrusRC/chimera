"""Per-tool pytest fixtures with availability-based skips."""
from __future__ import annotations

import pytest

from chimera.adapters.ghidra import GhidraAdapter
from chimera.adapters.jadx import JadxAdapter
from chimera.adapters.radare2 import Radare2Adapter


def _skip_if_unavailable(adapter, name: str):
    if not adapter.is_available():
        pytest.skip(f"{name} binary not on PATH")
    return adapter


@pytest.fixture
def jadx_adapter():
    return _skip_if_unavailable(JadxAdapter(), "jadx")


@pytest.fixture
def radare2_adapter():
    return _skip_if_unavailable(Radare2Adapter(), "radare2")


@pytest.fixture
def ghidra_adapter():
    return _skip_if_unavailable(GhidraAdapter(), "ghidra")
