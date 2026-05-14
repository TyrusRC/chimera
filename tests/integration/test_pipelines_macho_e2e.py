"""End-to-end standalone Mach-O pipeline test against tests/fixtures/macho/tiny.macho."""
import asyncio
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "macho" / "tiny.macho"


@pytest.mark.skipif(not FIXTURE.exists(), reason="Mach-O fixture missing — run tests/fixtures/macho/_build.py")
def test_macho_pipeline_end_to_end(tmp_path):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.model.binary import BinaryFormat

    config = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(config)
    try:
        model = asyncio.run(engine.analyze(str(FIXTURE)))
    finally:
        asyncio.run(engine.cleanup())

    assert model is not None
    assert model.binary.format == BinaryFormat.MACHO
    # Pipeline must not crash on a minimal header; functions/strings can be empty.
    assert isinstance(model.functions, list)
    assert isinstance(model.get_strings(), list)
