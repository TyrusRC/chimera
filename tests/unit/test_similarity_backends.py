"""Tests for the pluggable similarity-backend hook."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest

from chimera.diff.function_similarity import (
    available_backends,
    diff_iterables,
    get_similarity_backend,
    register_similarity_backend,
)


@dataclass
class _F:
    address: str
    name: str
    disassembly: Optional[list[dict]] = None
    decompiled: Optional[str] = None
    original_name: str = ""
    language: str = "c"
    classification: str = "unknown"
    layer: str = "native"
    source_backend: str = "test"
    signature: Optional[str] = None
    ai_renamed: bool = False
    ai_comments: Optional[str] = None
    sources: list = field(default_factory=list)
    metadata: Optional[dict] = None


def test_jaccard_remains_default_backend():
    assert "jaccard" in available_backends()
    a = [_F("0x1000", "f", decompiled="int x = 1;")]
    b = [_F("0x2000", "f", decompiled="int x = 1;")]
    # No backend arg → Jaccard.
    r = diff_iterables(a, b)
    # Default should not stamp a `backend` key — preserves prior shape.
    assert "backend" not in r or r.get("backend") == "jaccard"


def test_unknown_backend_raises_clear_error():
    a = [_F("0x1000", "f")]
    b = [_F("0x2000", "f")]
    with pytest.raises(ValueError) as exc_info:
        diff_iterables(a, b, backend="nonsense")
    assert "not registered" in str(exc_info.value)


def test_custom_backend_drives_full_diff_pipeline():
    class _AlwaysOne:
        name = "always-one"

        def fingerprint(self, func):
            return (func.name or func.address), "synthetic"

        def similarity(self, x, y):
            return 1.0 if x == y else 0.0

    register_similarity_backend("always-one", _AlwaysOne())
    assert get_similarity_backend("always-one") is not None
    assert "always-one" in available_backends()

    a = [_F("0x1000", "encode"), _F("0x1100", "extra_a")]
    b = [_F("0x2000", "encode"), _F("0x2200", "extra_b")]
    r = diff_iterables(a, b, backend="always-one")
    assert r["backend"] == "always-one"
    assert r["totals"]["matched"] == 1
    assert r["matched"][0]["a_name"] == "encode"
    assert r["matched"][0]["fingerprint"].startswith("always-one:")
    # Each side has one leftover (extra_a / extra_b) — they don't share
    # a fingerprint, so they end up in removed/added.
    assert r["totals"]["removed"] == 1
    assert r["totals"]["added"] == 1


def test_register_is_idempotent():
    class _Stub:
        name = "stub"
        def fingerprint(self, f): return (f.name, "stub")
        def similarity(self, a, b): return 0.5

    register_similarity_backend("stub", _Stub())
    register_similarity_backend("stub", _Stub())  # second call must not raise
    assert available_backends().count("stub") == 1
