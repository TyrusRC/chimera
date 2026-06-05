"""Tests for the DecLLM-style recompile gate (chimera.ai.recompile)."""

from __future__ import annotations

import asyncio
import os
import shutil

import pytest

from chimera.ai.recompile import recompile_check


pytestmark = pytest.mark.skipif(
    not (shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")),
    reason="no C compiler on PATH",
)


def test_valid_c_passes():
    ok, errs = asyncio.run(recompile_check("int add(int a, int b) { return a + b; }"))
    assert ok is True
    assert errs == ""


def test_obviously_broken_c_fails():
    # Unbalanced braces + bogus token sequence — no -w can suppress this.
    ok, errs = asyncio.run(recompile_check("int foo() { @@@ unknown_macro ( "))
    assert ok is False
    assert errs  # we get *some* diagnostic back


def test_stdint_types_resolved_by_prelude():
    """The prelude declares uint32_t etc. so decompile snippets compile."""
    code = "uint32_t take(uint32_t x, size_t n) { return x + (uint32_t)n; }"
    ok, errs = asyncio.run(recompile_check(code))
    assert ok is True, errs


def test_truncates_error_tail():
    """A wall of errors must be capped to keep repair prompts small."""
    garbage = "@" * 50_000
    ok, errs = asyncio.run(recompile_check(garbage))
    assert ok is False
    assert len(errs) <= 2048


def test_missing_compiler_returns_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("CHIMERA_RECOMPILE_CC", "/nonexistent/cc-xxxxx")
    # The check should still attempt to invoke; subprocess failure surfaces
    # as ok=False. We don't assert on the exact message — just non-empty.
    ok, errs = asyncio.run(recompile_check("int x;"))
    assert ok is False
    assert errs
