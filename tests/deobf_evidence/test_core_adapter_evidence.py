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
