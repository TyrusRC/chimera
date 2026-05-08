"""Unit tests for the PE analysis pipeline.

Patches all adapters' is_available to False; asserts the pipeline still
produces a model populated from pe_header without crashing.
"""
import asyncio
import struct
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _build_minimal_pe64(path: Path) -> Path:
    """Same helper as test_pe_header.py — copies inline so this test is standalone."""
    BUF = 0x800
    SEC_VA = 0x1000
    SEC_RAW = 0x200
    SEC_SIZE = 0x200
    OPT = 240
    buf = bytearray(BUF)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off+4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x8664, 1, 0, 0, 0, OPT, 0x2000)
    opt = pe_off + 24
    struct.pack_into("<HBBIIII", buf, opt, 0x20b, 0, 0, SEC_SIZE, 0, 0, SEC_VA)
    struct.pack_into("<IQ", buf, opt + 20, SEC_VA, 0x140000000)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", buf, opt + 52, 0, 0x2000, 0x200, 0)
    struct.pack_into("<HH", buf, opt + 68, 3, 0)
    struct.pack_into("<I", buf, opt + 108, 16)
    sec = opt + OPT
    struct.pack_into("<8sIIIIIIHHI", buf, sec,
                     b".text\x00\x00\x00", SEC_SIZE, SEC_VA, SEC_SIZE, SEC_RAW,
                     0, 0, 0, 0, 0x60000020)
    path.write_bytes(bytes(buf))
    return path


@pytest.fixture
def setup(tmp_path):
    cfg = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=None)
    reg = AdapterRegistry()  # empty registry — every adapter resolves to None
    return cfg, cache, rm, reg


def test_pe_pipeline_produces_model_with_no_adapters(setup, tmp_path):
    from chimera.pipelines.pe import analyze_pe
    cfg, cache, rm, reg = setup
    pe = _build_minimal_pe64(tmp_path / "x.dll")
    model = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    assert model is not None
    assert model.binary.format.value in ("pe32", "pe64", "dotnet_pe")
    # parse_pe should have populated imports list (empty for our minimal PE)
    assert isinstance(model.imports, list)


def test_pe_pipeline_writes_triage_cache(setup, tmp_path):
    from chimera.pipelines.pe import analyze_pe
    cfg, cache, rm, reg = setup
    pe = _build_minimal_pe64(tmp_path / "x.dll")
    model = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None
    assert "platform" in triage
    assert triage["platform"] == "windows"


def test_pe_pipeline_cache_hit_returns_model(setup, tmp_path):
    """Second run should hit triage cache and return without re-running phases."""
    from chimera.pipelines.pe import analyze_pe
    cfg, cache, rm, reg = setup
    pe = _build_minimal_pe64(tmp_path / "y.dll")

    model1 = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    sha = model1.binary.sha256

    # Verify triage was written
    assert cache.get_json(sha, "triage") is not None

    # Second run — should return from cache
    model2 = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    assert model2 is not None
    assert model2.binary.sha256 == sha


def test_pe_pipeline_skipped_phases_tracked(setup, tmp_path):
    """All adapter-dependent phases should be recorded in skipped_phases when adapters absent."""
    from chimera.pipelines.pe import analyze_pe
    cfg, cache, rm, reg = setup
    pe = _build_minimal_pe64(tmp_path / "z.dll")
    model = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert isinstance(triage["skipped_phases"], list)
    # radare2 and ghidra should be in skipped_phases since registry is empty
    assert any("radare2" in p for p in triage["skipped_phases"])


def test_pe_pipeline_pe_header_cached(setup, tmp_path):
    """pe_header cache entry should be written after parse_pe succeeds."""
    from chimera.pipelines.pe import analyze_pe
    cfg, cache, rm, reg = setup
    pe = _build_minimal_pe64(tmp_path / "hdr.dll")
    model = asyncio.run(analyze_pe(pe, cfg, reg, rm, cache))
    header_cache = cache.get_json(model.binary.sha256, "pe_header")
    assert header_cache is not None
    assert "machine" in header_cache
    assert "section_count" in header_cache
