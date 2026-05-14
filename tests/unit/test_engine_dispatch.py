"""Engine dispatch tests for PE / ELF / standalone routing."""
import asyncio
import struct
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine
from chimera.model.binary import BinaryInfo
from chimera.model.program import UnifiedProgramModel


def _build_minimal_pe64(tmp_path: Path) -> Path:
    """Build a tiny valid PE32+ for dispatch testing."""
    p = tmp_path / "x.exe"
    buf = bytearray(b"\x00" * 0x800)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off+4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x8664, 1, 0, 0, 0, 0, 0)
    struct.pack_into("<H", buf, pe_off + 24, 0x20b)
    p.write_bytes(bytes(buf))
    return p


def _build_minimal_elf(tmp_path: Path) -> Path:
    p = tmp_path / "hello"
    # 0x7fELF + 16 bytes class/data/version/etc
    p.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 100)
    return p


def test_engine_routes_pe_to_analyze_pe(tmp_path):
    pe = _build_minimal_pe64(tmp_path)
    config = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    eng = ChimeraEngine(config)
    fake_model = UnifiedProgramModel(BinaryInfo.from_path(pe))
    with patch("chimera.pipelines.pe.analyze_pe", new=AsyncMock(return_value=fake_model)) as fake:
        asyncio.run(eng.analyze(str(pe)))
        fake.assert_awaited_once()


def test_engine_routes_standalone_elf_to_analyze_elf(tmp_path):
    elf = _build_minimal_elf(tmp_path)
    config = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    eng = ChimeraEngine(config)
    fake_model = UnifiedProgramModel(BinaryInfo.from_path(elf))
    with patch("chimera.pipelines.elf.analyze_elf", new=AsyncMock(return_value=fake_model)) as fake:
        asyncio.run(eng.analyze(str(elf)))
        fake.assert_awaited_once()


def test_engine_routes_memory_image_to_analyze_memory(tmp_path):
    img = tmp_path / "core.lime"
    img.write_bytes(b"LiME" + b"\x00" * 200)
    config = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    eng = ChimeraEngine(config)
    fake_model = UnifiedProgramModel(BinaryInfo.from_path(img))
    with patch("chimera.pipelines.memory.analyze_memory",
               new=AsyncMock(return_value=fake_model)) as fake:
        asyncio.run(eng.analyze(str(img)))
        fake.assert_awaited_once()


def test_engine_rejects_unknown_format(tmp_path):
    from chimera.core.engine import UnsupportedFormatError
    p = tmp_path / "garbage.bin"
    p.write_bytes(b"\x00" * 100)
    config = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    eng = ChimeraEngine(config)
    with pytest.raises(UnsupportedFormatError, match="Unsupported format"):
        asyncio.run(eng.analyze(str(p)))


def test_detect_platform_classifies_top_level_elf_as_linux_native(tmp_path):
    from chimera.pipelines.common import detect_platform
    elf = _build_minimal_elf(tmp_path)
    assert detect_platform(elf) == "linux_native"


def test_detect_platform_classifies_bionic_so_as_android(tmp_path):
    from chimera.pipelines.common import detect_platform
    p = tmp_path / "lib.so"
    # ELF magic + filler containing the Bionic marker
    p.write_bytes(b"\x7fELF" + b"\x00" * 200 + b"liblog.so" + b"\x00" * 200)
    assert detect_platform(p) == "android"


def test_detect_binary_format_classifies_pe(tmp_path):
    from chimera.pipelines.common import detect_binary_format
    pe = _build_minimal_pe64(tmp_path)
    assert detect_binary_format(pe) == "pe64"
