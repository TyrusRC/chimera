from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _minimal_ipa(p: Path) -> None:
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", b"<?xml version=\"1.0\"?><plist/>")


async def test_ios_cache_hit_short_circuits(tmp_path):
    from chimera.pipelines.ios import analyze_ipa
    ipa = tmp_path / "t.ipa"
    _minimal_ipa(ipa)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(ipa)
    cache.put_json(binary.sha256, "triage", {
        "platform": "ios", "framework": "native", "bundle_id": "com.example",
        "binary_count": 0, "framework_count": 0, "extension_count": 0,
        "function_count": 0, "string_count": 0,
    })

    model = await analyze_ipa(ipa, cfg, registry, rm, cache)
    unpacked = cfg.project_dir / "unpacked"
    assert not unpacked.exists(), "cache hit must short-circuit before unpack"
    assert model.binary.sha256 == binary.sha256
