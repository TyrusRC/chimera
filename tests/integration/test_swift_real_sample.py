"""Real-file integration test for the iOS Swift demangle phase.

Bring-your-own-sample: drop sample.ipa under e2e/material/swift-ios. The test
skips when no sample is present. Optional sibling expected.json upgrades from
smoke assertions to tight ones.
"""

from __future__ import annotations

import json
import shutil
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


async def test_swift_ios_real_pipeline(tmp_path):
    sample = SLOT / "sample.ipa"
    if not sample.exists():
        pytest.skip(f"no sample at {sample}; drop a real IPA to enable this test")

    config = ChimeraConfig(project_dir=tmp_path / "project", cache_dir=tmp_path / "cache")
    engine = ChimeraEngine(config)
    model = await engine.analyze(sample)

    cache = AnalysisCache(config.cache_dir)
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None, "triage cache empty"
    ctx = triage.get("swift_demangle_context")
    assert ctx is not None, "swift_demangle_context missing from triage"

    have_tool = shutil.which("swift-demangle") is not None
    assert ctx["available"] == have_tool, f"available={ctx['available']} but tool present={have_tool}"

    if have_tool:
        assert ctx["names_demangled"] > 0, "expected at least one demangled function name"

    expected = _load_expected(SLOT)
    if expected is None:
        return

    if "min_names_demangled" in expected:
        assert ctx["names_demangled"] >= expected["min_names_demangled"]
    if "must_find_demangled_substring" in expected:
        needle = expected["must_find_demangled_substring"]
        names = " ".join(f.name for f in model.functions)
        assert needle in names, f"expected {needle!r} in demangled function names"
