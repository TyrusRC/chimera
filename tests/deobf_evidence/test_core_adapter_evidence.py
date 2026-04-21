"""Core adapter evidence tests (jadx, radare2, ghidra, class-dump)."""
from __future__ import annotations

import re

import pytest

from tests.deobf_evidence._assertions import (
    assert_min_count,
    assert_names_contain,
    assert_no_obfuscated_short_names,
)
from tests.deobf_evidence._fixtures import build_sample, load_expected
from tests.deobf_evidence._registry import register_evidence


@register_evidence("jadx", "android-proguard-rename")
@pytest.mark.asyncio
async def test_jadx_recovers_proguard_classes(jadx_adapter, tmp_path):
    sample = build_sample("android-proguard-rename")
    expected = load_expected("android-proguard-rename")["expected"]["jadx"]

    result = await jadx_adapter.analyze(str(sample), {"output_dir": str(tmp_path)})

    assert_min_count(
        result["decompiled_files"], expected["min_decompiled_files"], "decompiled_files"
    )
    all_classes = result["class_basenames"]
    assert_names_contain(all_classes, expected["class_names_contain"])
    assert_no_obfuscated_short_names(all_classes, expected["class_names_do_not_contain_regex"])


@register_evidence("jadx", "android-xor-string")
@pytest.mark.asyncio
async def test_jadx_does_not_decrypt_xor_strings(jadx_adapter, tmp_path):
    """Asserts the limit: jadx recovers the decrypt() method but not its output."""
    from pathlib import Path

    sample = build_sample("android-xor-string")
    expected = load_expected("android-xor-string")["expected"]["jadx"]
    result = await jadx_adapter.analyze(str(sample), {"output_dir": str(tmp_path)})

    sources = Path(result["sources_dir"])
    all_text = "\n".join(
        p.read_text(errors="replace") for p in sources.rglob("*.java")
    )

    assert "decrypt" in all_text, "jadx should recover the decrypt() method name"
    plaintext = expected["plaintext_that_must_not_appear"]
    assert plaintext not in all_text, (
        f"Plaintext {plaintext!r} appeared in jadx output — jadx is NOT expected "
        f"to perform XOR decryption at this layer. Decryption is Sub-project 2's job."
    )


@register_evidence("radare2", "android-native-stripped")
@pytest.mark.asyncio
async def test_radare2_recovers_functions_on_stripped_arm64(radare2_adapter):
    sample = build_sample("android-native-stripped")
    expected = load_expected("android-native-stripped")["expected"]["radare2"]

    result = await radare2_adapter.analyze(str(sample), {"mode": "full"})

    funcs = result.get("functions", [])
    assert_min_count(len(funcs), expected["min_functions"], "radare2 functions")

    with_xrefs = [f for f in funcs if f.get("nbbs", 0) >= 1 and f.get("size", 0) > 0]
    assert_min_count(
        len(with_xrefs),
        expected["min_functions_with_xrefs"],
        "r2 functions with body",
    )

    strings = [s.get("string") for s in result.get("strings", []) if isinstance(s, dict)]
    assert any(expected["must_find_string"] in s for s in strings if s), (
        f"Expected string {expected['must_find_string']!r} not found"
    )


@register_evidence("ghidra", "android-native-stripped")
@pytest.mark.asyncio
async def test_ghidra_recovers_functions_on_stripped_arm64(ghidra_adapter, tmp_path):
    sample = build_sample("android-native-stripped")
    expected = load_expected("android-native-stripped")["expected"]["ghidra"]

    result = await ghidra_adapter.analyze(str(sample), {"project_dir": str(tmp_path)})
    functions = result.get("functions", [])
    strings = result.get("strings", [])

    assert_min_count(len(functions), expected["min_functions"], "ghidra functions")
    string_values = [s.get("value") for s in strings if isinstance(s, dict)]
    assert any(expected["must_find_string"] in (v or "") for v in string_values), (
        f"Expected string not in {len(string_values)} ghidra strings"
    )
