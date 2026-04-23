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
