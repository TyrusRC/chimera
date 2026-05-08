"""End-to-end PE pipeline test against tests/fixtures/pe/hello.exe."""
import asyncio
import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "pe" / "hello.exe"


@pytest.mark.skipif(not FIXTURE.exists(), reason="PE fixture missing")
def test_pe_pipeline_end_to_end(tmp_path):
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
    assert model.binary.format in (BinaryFormat.PE32, BinaryFormat.PE64, BinaryFormat.DOTNET_PE)
    # Synthetic fixture has no imports; real mingw fixture should have several.
    # Either way pipeline shouldn't crash.
    assert isinstance(model.imports, list)
