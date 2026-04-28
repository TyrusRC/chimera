"""Real-file integration test for the ObjC cross-reference phase.

Reuses the SP5 e2e/material/swift-ios slot. Skips when no sample.ipa
is present. Optional sibling expected.json upgrades smoke assertions
to tight ones.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine

REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT = REPO_ROOT / "e2e" / "material" / "swift-ios"


def _load_expected(slot: Path) -> dict | None:
    expected = slot / "expected.json"
    if not expected.exists():
        return None
    try:
        return json.loads(expected.read_text())
    except (OSError, json.JSONDecodeError):
        return None


async def test_objc_xref_real_pipeline(tmp_path):
    sample = SLOT / "sample.ipa"
    if not sample.exists():
        pytest.skip(f"no sample at {sample}; drop a real IPA to enable this test")

    config = ChimeraConfig(project_dir=tmp_path / "project",
                            cache_dir=tmp_path / "cache")
    engine = ChimeraEngine(config)
    model = await engine.analyze(sample)

    cache = AnalysisCache(config.cache_dir)
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None, "triage cache empty"
    ctx = triage.get("objc_xref_context")
    assert ctx is not None, "objc_xref_context missing"
    assert ctx["available"] is True, f"parser failed: {ctx.get('skipped_reason')}"
    # Smoke: any non-trivial Swift app has @objc classes (at minimum AppDelegate).
    assert ctx["class_count"] >= 1
    assert ctx["method_count"] >= 1

    expected = _load_expected(SLOT)
    if expected is None:
        return
    if "min_objc_classes" in expected:
        assert ctx["class_count"] >= expected["min_objc_classes"]
    if "must_find_objc_selector" in expected:
        sels = [m.selector for m in model.objc_methods]
        assert expected["must_find_objc_selector"] in sels
