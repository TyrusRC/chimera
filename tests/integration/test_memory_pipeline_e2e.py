"""End-to-end memory pipeline test against the synthetic LiME fixture.

The synthetic fixture is small and doesn't carry real Linux kernel data,
so Volatility plugins will fail to extract anything meaningful — but the
pipeline itself must not crash, and it must classify the image as
linux_memory and write a triage cache entry.

Skipped when the fixture is missing.
"""
import asyncio
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "memory" / "sample.lime"


@pytest.mark.skipif(not FIXTURE.exists(), reason="LiME fixture missing")
def test_memory_pipeline_end_to_end(tmp_path):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(config)
    try:
        model = asyncio.run(engine.analyze(str(FIXTURE)))
    finally:
        asyncio.run(engine.cleanup())

    assert model is not None
    from chimera.model.binary import BinaryFormat, Platform
    assert model.binary.format == BinaryFormat.MEMORY_LIME
    assert model.binary.platform == Platform.LINUX_MEMORY


@pytest.mark.skipif(not FIXTURE.exists(), reason="LiME fixture missing")
def test_memory_pipeline_writes_triage(tmp_path):
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(config)
    try:
        model = asyncio.run(engine.analyze(str(FIXTURE)))
    finally:
        asyncio.run(engine.cleanup())

    cache = AnalysisCache(config.cache_dir)
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None
    assert triage["platform"] == "linux_memory"
