"""Shared assertion helpers for evidence tests."""
from __future__ import annotations

import re


def assert_no_obfuscated_short_names(names: list[str], pattern: str = r"^[a-z]$") -> None:
    rx = re.compile(pattern)
    bad = [n for n in names if rx.match(n)]
    assert not bad, f"Obfuscated names remain: {bad[:10]}"


def assert_names_contain(names: list[str], required: list[str]) -> None:
    missing = [r for r in required if not any(r in n for n in names)]
    assert not missing, f"Expected names missing: {missing}"


def assert_min_count(got: int, want_min: int, what: str) -> None:
    assert got >= want_min, f"{what}: got {got}, want >= {want_min}"


def assert_string_present(strings: list[str], needle: str) -> None:
    assert any(needle in s for s in strings), f"String {needle!r} not found among {len(strings)} strings"
