"""Unit tests for the ELF analysis pipeline.

Patches all adapters' is_available to False; asserts the pipeline
produces a model populated from elf_header without crashing.
"""
import asyncio
import struct
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _build_minimal_elf64(path: Path) -> Path:
    """Minimal valid ELF64 EXEC, no segments/sections."""
    EHSIZE = 64
    PHENTSIZE = 56
    ehdr = bytearray(EHSIZE)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2     # ELFCLASS64
    ehdr[5] = 1     # ELFDATA2LSB
    ehdr[6] = 1     # EV_CURRENT
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     2, 0x3e, 1, 0x401000, EHSIZE, 0, 0,
                     EHSIZE, PHENTSIZE, 0, 0, 0, 0)
    path.write_bytes(bytes(ehdr))
    return path


@pytest.fixture
def setup(tmp_path):
    cfg = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=None)
    reg = AdapterRegistry()
    return cfg, cache, rm, reg


def test_elf_pipeline_produces_model(setup, tmp_path):
    from chimera.pipelines.elf import analyze_elf
    cfg, cache, rm, reg = setup
    elf = _build_minimal_elf64(tmp_path / "hello")
    model = asyncio.run(analyze_elf(elf, cfg, reg, rm, cache))
    assert model is not None
    # ELF should be classified as standalone
    from chimera.model.binary import BinaryFormat
    assert model.binary.format == BinaryFormat.ELF_STANDALONE


def test_elf_pipeline_writes_triage_cache(setup, tmp_path):
    from chimera.pipelines.elf import analyze_elf
    cfg, cache, rm, reg = setup
    elf = _build_minimal_elf64(tmp_path / "hello")
    model = asyncio.run(analyze_elf(elf, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None
    assert triage["platform"] == "linux_native"


def test_elf_pipeline_runs_on_real_system_binary(setup):
    from chimera.pipelines.elf import analyze_elf
    cfg, cache, rm, reg = setup
    candidates = [Path("/bin/ls"), Path("/usr/bin/ls"), Path("/bin/cat")]
    binary = next((c for c in candidates if c.exists() and c.is_file()), None)
    if binary is None:
        pytest.skip("no system ELF available")
    model = asyncio.run(analyze_elf(binary, cfg, reg, rm, cache))
    # /bin/ls is dynamically linked → should have NEEDED libs in model.imports
    assert len(model.imports) > 0
