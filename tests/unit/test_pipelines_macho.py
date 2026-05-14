"""Unit tests for the standalone Mach-O analysis pipeline.

Mirrors test_pipelines_pe.py / test_pipelines_elf.py: an empty adapter
registry forces every external-tool phase down its skipped branch, and the
pipeline must still produce a populated UnifiedProgramModel from header
parsing alone.
"""
from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryFormat


def _build_minimal_macho64(path: Path) -> Path:
    """Minimal valid 64-bit Mach-O header (no load commands).

    Layout matches `struct mach_header_64` (little-endian on x86_64):
      magic(u32) cputype(u32) cpusubtype(u32) filetype(u32)
      ncmds(u32) sizeofcmds(u32) flags(u32) reserved(u32)
    """
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,        # MH_MAGIC_64
        0x01000007,        # cputype: CPU_TYPE_X86_64
        3,                 # cpusubtype
        2,                 # filetype: MH_EXECUTE
        0,                 # ncmds
        0,                 # sizeofcmds
        0,                 # flags
        0,                 # reserved
    )
    path.write_bytes(header)
    return path


def _build_minimal_dylib(path: Path) -> Path:
    """Mach-O DYLIB — same shape as the executable but filetype=MH_DYLIB (6)."""
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        6,                 # filetype: MH_DYLIB
        0, 0, 0, 0,
    )
    path.write_bytes(header)
    return path


def _build_minimal_fat(path: Path) -> Path:
    """FAT/Universal binary — magic 0xCAFEBABE with zero embedded slices."""
    # magic(u32, big-endian) nfat_arch(u32, big-endian)
    header = struct.pack(">II", 0xCAFEBABE, 0)
    path.write_bytes(header)
    return path


@pytest.fixture
def setup(tmp_path):
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=None)
    reg = AdapterRegistry()  # empty — every adapter resolves to None
    return cfg, cache, rm, reg


def test_macho_pipeline_produces_model(setup, tmp_path):
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    macho = _build_minimal_macho64(tmp_path / "tiny.macho")
    model = asyncio.run(analyze_macho(macho, cfg, reg, rm, cache))
    assert model is not None
    assert model.binary.format == BinaryFormat.MACHO


def test_macho_pipeline_handles_dylib(setup, tmp_path):
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    dylib = _build_minimal_dylib(tmp_path / "libtest.dylib")
    model = asyncio.run(analyze_macho(dylib, cfg, reg, rm, cache))
    assert model is not None
    # .dylib suffix takes the format_map fast path → DYLIB
    assert model.binary.format in (BinaryFormat.MACHO, BinaryFormat.DYLIB)


def test_macho_pipeline_handles_fat(setup, tmp_path):
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    fat = _build_minimal_fat(tmp_path / "fat.bin")
    model = asyncio.run(analyze_macho(fat, cfg, reg, rm, cache))
    assert model is not None
    assert model.binary.format == BinaryFormat.FAT


def test_macho_pipeline_writes_triage_cache(setup, tmp_path):
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    macho = _build_minimal_macho64(tmp_path / "tiny.macho")
    model = asyncio.run(analyze_macho(macho, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None
    assert triage["platform"] == "ios"
    assert "skipped_phases" in triage


def test_macho_pipeline_cache_hit_returns_model(setup, tmp_path):
    """Second run should hit triage cache and return without re-running phases."""
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    macho = _build_minimal_macho64(tmp_path / "tiny.macho")

    model1 = asyncio.run(analyze_macho(macho, cfg, reg, rm, cache))
    sha = model1.binary.sha256
    assert cache.get_json(sha, "triage") is not None

    model2 = asyncio.run(analyze_macho(macho, cfg, reg, rm, cache))
    assert model2 is not None
    assert model2.binary.sha256 == sha


def test_macho_pipeline_skipped_phases_tracked(setup, tmp_path):
    """All adapter-dependent phases should be recorded in skipped_phases when adapters absent."""
    from chimera.pipelines.macho import analyze_macho
    cfg, cache, rm, reg = setup
    macho = _build_minimal_macho64(tmp_path / "tiny.macho")
    model = asyncio.run(analyze_macho(macho, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert isinstance(triage["skipped_phases"], list)
    # radare2 must be reported skipped when registry is empty
    assert any("radare2" in p for p in triage["skipped_phases"])


def test_engine_dispatch_routes_macho_to_standalone(setup, tmp_path, monkeypatch):
    """engine.analyze must dispatch a bare Mach-O to analyze_macho, not analyze_ipa."""
    from chimera.core.engine import ChimeraEngine
    cfg, _cache, _rm, _reg = setup
    macho = _build_minimal_macho64(tmp_path / "tiny.macho")

    called = {"macho": 0, "ipa": 0}

    async def _fake_macho(path, config, registry, resource_mgr, cache):
        called["macho"] += 1
        from chimera.model.binary import BinaryInfo
        from chimera.model.program import UnifiedProgramModel
        return UnifiedProgramModel(BinaryInfo.from_path(path))

    async def _fake_ipa(path, config, registry, resource_mgr, cache):
        called["ipa"] += 1
        from chimera.model.binary import BinaryInfo
        from chimera.model.program import UnifiedProgramModel
        return UnifiedProgramModel(BinaryInfo.from_path(path))

    monkeypatch.setattr("chimera.pipelines.macho.analyze_macho", _fake_macho)
    monkeypatch.setattr("chimera.pipelines.ios.analyze_ipa", _fake_ipa)

    engine = ChimeraEngine(cfg)
    asyncio.run(engine.analyze(macho))
    assert called["macho"] == 1
    assert called["ipa"] == 0
