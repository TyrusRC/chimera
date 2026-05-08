"""End-to-end ELF pipeline test against tests/fixtures/elf/hello."""
import asyncio
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "elf" / "hello"


@pytest.mark.skipif(not FIXTURE.exists(), reason="ELF fixture missing")
def test_elf_pipeline_end_to_end(tmp_path):
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
    assert model.binary.format == BinaryFormat.ELF_STANDALONE
    # static-linked binary has no DT_NEEDED, but pipeline should still produce a model
    assert isinstance(model.imports, list)
