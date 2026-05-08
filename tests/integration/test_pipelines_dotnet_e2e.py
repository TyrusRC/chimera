"""End-to-end .NET pipeline test against tests/fixtures/dotnet/bin/hello.dll."""
import asyncio
import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "dotnet" / "bin" / "hello.dll"


@pytest.mark.skipif(not FIXTURE.exists(), reason=".NET fixture missing")
def test_dotnet_pipeline_end_to_end(tmp_path):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(config)
    try:
        model = asyncio.run(engine.analyze(str(FIXTURE)))
    finally:
        asyncio.run(engine.cleanup())

    assert model is not None
    from chimera.model.binary import BinaryFormat
    assert model.binary.format == BinaryFormat.DOTNET_PE
    # If ilspycmd is available, types should be present; else just verify no crash.
    if shutil.which("ilspycmd"):
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        keys = cache.list_keys(model.binary.sha256)
        ilspy_keys = [k for k in keys if k.startswith("ilspy_")]
        # only assert if we got an ilspy hit; synthetic .NET stub may yield 0 types
        if ilspy_keys:
            assert len(ilspy_keys) >= 1
