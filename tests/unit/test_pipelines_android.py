"""Android pipeline orchestration behavior."""
from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _minimal_apk(p: Path) -> None:
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00")


async def test_android_cache_hit_short_circuits(tmp_path, caplog):
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "t.apk"
    _minimal_apk(apk)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(apk)
    cache.put_json(binary.sha256, "triage", {
        "platform": "android", "format": "apk", "framework": "native",
        "dex_count": 1, "has_native": False, "native_lib_count": 0,
        "function_count": 0, "string_count": 0, "bundle_format": None,
    })

    with caplog.at_level("INFO"):
        model = await analyze_apk(apk, cfg, registry, rm, cache)

    unpacked = cfg.project_dir / "unpacked"
    assert not unpacked.exists(), (
        "cache hit must short-circuit before unpack; found %s" % list(unpacked.rglob("*"))
        if unpacked.exists() else ""
    )
    assert model.binary.sha256 == binary.sha256


async def test_android_cache_hit_rehydrates_functions_and_strings(tmp_path):
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "r.apk"
    _minimal_apk(apk)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(apk)
    cache.put_json(binary.sha256, "triage", {"platform": "android", "framework": "native"})
    cache.put_json(binary.sha256, "r2_libfoo.so", {
        "strings": [{"string": "hello", "vaddr": 0x1000}],
        "functions": [{"name": "foo", "offset": 0x2000}],
    })

    model = await analyze_apk(apk, cfg, registry, rm, cache)
    assert [s.value for s in model.get_strings()] == ["hello"]
    assert [f.name for f in model.functions] == ["foo"]


async def test_android_r2_malformed_output_does_not_crash(tmp_path):
    """r2 returning garbage in 'strings' or 'functions' lists must be filtered, not crash."""
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "m.apk"
    _minimal_apk(apk)
    # Add a native library so r2 phase runs
    import zipfile
    with zipfile.ZipFile(apk, "a") as zf:
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 100)

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    class FakeR2:
        def name(self): return "radare2"
        def is_available(self): return True
        def supported_formats(self): return ["elf"]
        async def analyze(self, path, opts):
            return {
                "strings": [
                    {"string": "good", "vaddr": 0x1000},
                    "not-a-dict",
                    {"no_string_key": True},
                    {"string": 12345, "vaddr": "bad"},  # string value is int
                ],
                "functions": [
                    {"name": "ok", "offset": 0x2000},
                    {"no_address_at_all": True},
                    "garbage",
                ],
                "imports": [],
                "info": {}, "core": {},
            }
        async def cleanup(self): pass

    registry = AdapterRegistry()
    registry.register(FakeR2())

    model = await analyze_apk(apk, cfg, registry, rm, cache)
    string_values = [s.value for s in model.get_strings()]
    assert "good" in string_values
    assert all(isinstance(v, str) for v in string_values)
    fn_names = [f.name for f in model.functions]
    assert "ok" in fn_names
    assert "garbage" not in fn_names


async def test_android_skipped_phases_recorded_in_triage(tmp_path):
    """When r2/jadx/ghidra are missing, triage entry must list them as skipped."""
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "a.apk"
    _minimal_apk(apk)
    # Add a native lib so r2/ghidra phases are reachable
    import zipfile
    with zipfile.ZipFile(apk, "a") as zf:
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 100)

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()  # empty

    await analyze_apk(apk, cfg, registry, rm, cache)
    from chimera.model.binary import BinaryInfo
    triage = cache.get_json(BinaryInfo.from_path(apk).sha256, "triage")
    assert "skipped_phases" in triage
    assert "radare2" in triage["skipped_phases"]
    assert "jadx" in triage["skipped_phases"]
    assert "ghidra" in triage["skipped_phases"]
