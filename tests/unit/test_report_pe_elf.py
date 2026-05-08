"""Tests for the new PE/ELF/.NET report sections."""
from pathlib import Path
from unittest.mock import MagicMock

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import ImportEntry
from chimera.model.program import UnifiedProgramModel


class _StubCache:
    def __init__(self, blobs: dict | None = None):
        self.cache_dir = Path("/tmp/no-such-cache")
        self._blobs = blobs or {}

    def get_json(self, sha, key):
        return self._blobs.get(key)

    def get(self, sha, key):
        return None

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _model_for_pe(tmp_path):
    bi = BinaryInfo(
        sha256="f" * 64, path=tmp_path / "x.exe",
        format=BinaryFormat.PE32, platform=Platform.WINDOWS,
        arch=Architecture.X86, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    m.add_import(ImportEntry(dll="kernel32.dll", name="VirtualAllocEx",
                             address="0x401000", bucket="process_injection"))
    m.add_import(ImportEntry(dll="kernel32.dll", name="WriteProcessMemory",
                             bucket="process_injection"))
    return m


def test_report_includes_pe_imports_section(tmp_path):
    from chimera.report import build_report
    m = _model_for_pe(tmp_path)
    cache = _StubCache({
        "pe_imports": {
            "process_injection": {"imports": ["VirtualAllocEx"], "score": 1, "weight": 3.0},
        },
    })
    rep = build_report(m, cache)
    assert "pe_imports" in rep
    assert "process_injection" in rep["pe_imports"]


def test_report_includes_elf_persistence_section(tmp_path):
    from chimera.report import build_report
    bi = BinaryInfo(
        sha256="g" * 64, path=tmp_path / "x",
        format=BinaryFormat.ELF_STANDALONE, platform=Platform.LINUX_NATIVE,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    cache = _StubCache({
        "elf_persistence": [
            {"category": "cron", "path": "/etc/cron.d/", "evidence": "/etc/cron.d/x", "string_address": "0x1000"},
        ],
    })
    rep = build_report(m, cache)
    assert "elf_persistence" in rep
    assert len(rep["elf_persistence"]) == 1
    assert rep["elf_persistence"][0]["category"] == "cron"


def test_report_imports_array_truncated_at_500(tmp_path):
    from chimera.report import build_report
    m = _model_for_pe(tmp_path)
    for i in range(600):
        m.add_import(ImportEntry(dll="x.dll", name=f"fn_{i}"))
    cache = _StubCache({})
    rep = build_report(m, cache)
    assert "imports" in rep
    assert len(rep["imports"]) == 500


def test_report_native_protection_section(tmp_path):
    from chimera.report import build_report
    m = _model_for_pe(tmp_path)
    cache = _StubCache({
        "native_protection": {
            "packer": "VMProtect", "has_anti_debug": True, "has_anti_vm": False,
            "high_entropy_section_count": 2,
        },
    })
    rep = build_report(m, cache)
    assert rep["native_protection"]["packer"] == "VMProtect"
    assert rep["native_protection"]["has_anti_debug"] is True


def test_report_dotnet_assemblies_from_ilspy_keys(tmp_path):
    from chimera.report import build_report
    m = _model_for_pe(tmp_path)
    cache = _StubCache({
        "ilspy_myapp.dll": {
            "assembly": "MyApp",
            "types": [
                {"namespace": "MyApp", "name": "MainClass", "size_bytes": 1024},
            ],
        },
        "ilspy_helper.dll": {
            "assembly": "Helper",
            "types": [
                {"namespace": "Helper", "name": "Utils", "size_bytes": 512},
            ],
        },
    })
    rep = build_report(m, cache)
    assert "dotnet_assemblies" in rep
    assert len(rep["dotnet_assemblies"]) == 2
    assert rep["dotnet_assemblies"][0]["assembly"] in ["MyApp", "Helper"]


def test_report_all_new_keys_present(tmp_path):
    from chimera.report import build_report
    m = _model_for_pe(tmp_path)
    cache = _StubCache({
        "pe_header": {"dos_header": "..."},
        "pe_flags": {"has_debug": True},
        "elf_syscalls": {"read": 1, "write": 2},
    })
    rep = build_report(m, cache)
    assert "pe_header" in rep
    assert "pe_imports" in rep
    assert "pe_flags" in rep
    assert "elf_persistence" in rep
    assert "elf_syscalls" in rep
    assert "dotnet_assemblies" in rep
    assert "native_protection" in rep
    assert "imports" in rep
