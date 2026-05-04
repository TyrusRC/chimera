"""Unit tests for Ghidra cap behaviors in the Android pipeline."""

from __future__ import annotations

import zipfile
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager


class _FakeR2:
    def name(self): return "radare2"
    def is_available(self): return True
    def supported_formats(self): return ["elf"]
    async def analyze(self, path, opts):
        return {"strings": [], "functions": [], "info": {}, "core": {}, "imports": []}
    async def cleanup(self): pass


class _FakeGhidra:
    def __init__(self):
        self.calls: list[str] = []

    def name(self): return "ghidra"
    def is_available(self): return True
    def supported_formats(self): return ["elf"]
    async def analyze(self, path, opts):
        self.calls.append(Path(path).name)
        return {"return_code": 0}
    async def cleanup(self): pass


def _make_apk_with_libs(apk_path: Path, libs: dict[str, int]) -> None:
    """Create a minimal APK with native libs of given byte sizes."""
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"<?xml version='1.0'?><manifest package='x'/>\n")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        for name, size in libs.items():
            payload = b"\x7fELF" + b"\x00" * (size - 4)
            zf.writestr(f"lib/arm64-v8a/{name}", payload)


async def test_ghidra_skip_drops_phase_entirely(tmp_path):
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "a.apk"
    _make_apk_with_libs(apk, {"libfoo.so": 4096})
    cfg = ChimeraConfig(
        project_dir=tmp_path / "p",
        cache_dir=tmp_path / "c",
        ghidra_skip=True,
    )
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    fake_ghidra = _FakeGhidra()
    registry = AdapterRegistry()
    registry.register(_FakeR2())
    registry.register(fake_ghidra)

    await analyze_apk(apk, cfg, registry, rm, cache)

    assert fake_ghidra.calls == [], "ghidra_skip should drop the phase"
    triage = cache.get_json(_sha_of(apk), "triage")
    assert "ghidra" in (triage or {}).get("skipped_phases", [])


async def test_ghidra_size_cap_drops_oversized_libs(tmp_path):
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "b.apk"
    _make_apk_with_libs(apk, {
        "libsmall.so": 4096,
        "libhuge.so": 4 * 1024 * 1024,
    })
    cfg = ChimeraConfig(
        project_dir=tmp_path / "p",
        cache_dir=tmp_path / "c",
        ghidra_max_lib_mb=2,
    )
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    fake_ghidra = _FakeGhidra()
    registry = AdapterRegistry()
    registry.register(_FakeR2())
    registry.register(fake_ghidra)

    await analyze_apk(apk, cfg, registry, rm, cache)

    assert fake_ghidra.calls == ["libsmall.so"]
    triage = cache.get_json(_sha_of(apk), "triage") or {}
    skipped = {entry["lib"] for entry in triage.get("ghidra_skipped_libs") or []}
    assert "libhuge.so" in skipped


async def test_ghidra_max_libs_caps_count(tmp_path):
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "c.apk"
    libs = {f"lib{i}.so": 1024 for i in range(5)}
    _make_apk_with_libs(apk, libs)
    cfg = ChimeraConfig(
        project_dir=tmp_path / "p",
        cache_dir=tmp_path / "c",
        ghidra_max_libs=2,
    )
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    fake_ghidra = _FakeGhidra()
    registry = AdapterRegistry()
    registry.register(_FakeR2())
    registry.register(fake_ghidra)

    await analyze_apk(apk, cfg, registry, rm, cache)

    assert len(fake_ghidra.calls) == 2
    triage = cache.get_json(_sha_of(apk), "triage") or {}
    skipped = triage.get("ghidra_skipped_libs") or []
    assert len(skipped) == 3


def _sha_of(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
