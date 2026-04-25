"""Real-file integration tests for the React Native pipeline.

Bring-your-own-sample: drop sample.apk / sample.ipa under e2e/material/rn-android
or rn-ios. Tests skip when no sample is present. Optional sibling expected.json
upgrades from smoke assertions to tight ones.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine
from chimera.model.binary import Framework

REPO_ROOT = Path(__file__).resolve().parents[2]
ANDROID_SLOT = REPO_ROOT / "e2e" / "material" / "rn-android"
IOS_SLOT = REPO_ROOT / "e2e" / "material" / "rn-ios"


def _load_expected(slot: Path) -> dict | None:
    expected = slot / "expected.json"
    if not expected.exists():
        return None
    try:
        return json.loads(expected.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _smoke_assertions(triage: dict, ctx: dict, framework: Framework, expected: dict | None):
    assert framework == Framework.REACT_NATIVE, f"detector returned {framework}"
    assert ctx is not None, "react_native_context missing from triage"
    assert ctx["bundle_path"], "no bundle discovered"
    assert ctx["variant"] in {"hermes", "jsc"}, f"unexpected variant: {ctx['variant']}"

    if ctx["variant"] == "jsc":
        if shutil.which("webcrack"):
            assert ctx["decompile"]["ran"] is True or ctx["decompile"]["skipped_reason"] in (
                "decompile_failed", None,
            )
        else:
            assert ctx["decompile"]["skipped_reason"] == "tool_unavailable"
    else:
        if shutil.which("hermes-dec"):
            assert ctx["decompile"]["ran"] is True or ctx["decompile"]["skipped_reason"] in (
                "decompile_failed", None,
            )
        else:
            assert ctx["decompile"]["skipped_reason"] == "tool_unavailable"

    if expected is None:
        return

    if "variant" in expected:
        assert ctx["variant"] == expected["variant"], (
            f"variant mismatch: {ctx['variant']} != {expected['variant']}"
        )
    if "min_module_ids" in expected:
        assert ctx["module_id_count"] >= expected["min_module_ids"], (
            f"module_id_count {ctx['module_id_count']} < {expected['min_module_ids']}"
        )


async def test_rn_android_real_pipeline(tmp_path):
    sample = ANDROID_SLOT / "sample.apk"
    if not sample.exists():
        pytest.skip(f"no sample at {sample}; drop a real APK to enable this test")

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    engine = ChimeraEngine(config)
    model = await engine.analyze(sample)

    cache = AnalysisCache(config.cache_dir)
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None, "triage cache empty"
    ctx = triage.get("react_native_context")

    expected = _load_expected(ANDROID_SLOT)
    _smoke_assertions(triage, ctx, model.binary.framework, expected)

    if expected and "must_find_module" in expected:
        sources = cache.get_json(model.binary.sha256, "react_native_sources") or []
        assert any(expected["must_find_module"] in s for s in sources), (
            f"no source matched {expected['must_find_module']!r}; sources={sources[:5]!r}..."
        )
    if expected and "min_strings" in expected:
        assert len(model.get_strings()) >= expected["min_strings"]


async def test_rn_ios_real_pipeline(tmp_path):
    sample = IOS_SLOT / "sample.ipa"
    if not sample.exists():
        pytest.skip(f"no sample at {sample}; drop a real IPA to enable this test")

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    engine = ChimeraEngine(config)
    model = await engine.analyze(sample)

    cache = AnalysisCache(config.cache_dir)
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None, "triage cache empty"
    ctx = triage.get("react_native_context")

    expected = _load_expected(IOS_SLOT)
    _smoke_assertions(triage, ctx, model.binary.framework, expected)

    if expected and "must_find_module" in expected:
        sources = cache.get_json(model.binary.sha256, "react_native_sources") or []
        assert any(expected["must_find_module"] in s for s in sources)
    if expected and "min_strings" in expected:
        assert len(model.get_strings()) >= expected["min_strings"]
