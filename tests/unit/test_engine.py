"""Engine-level cleanup behavior."""
from __future__ import annotations

import pytest

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine


class _BadAdapter:
    def name(self) -> str:
        return "bad"

    def is_available(self) -> bool:
        return False

    async def cleanup(self) -> None:
        raise RuntimeError("simulated adapter cleanup failure")


class _GoodAdapter:
    def __init__(self) -> None:
        self.cleaned = False

    def name(self) -> str:
        return "good"

    def is_available(self) -> bool:
        return False

    async def cleanup(self) -> None:
        self.cleaned = True


async def test_cleanup_survives_one_failing_adapter(tmp_path, caplog):
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    engine = ChimeraEngine(cfg)
    good = _GoodAdapter()
    engine.registry._adapters.clear()
    engine.registry.register(_BadAdapter())
    engine.registry.register(good)

    with caplog.at_level("WARNING"):
        await engine.cleanup()

    assert good.cleaned is True, "good adapter must be cleaned even after bad raised"
    assert any("bad" in r.message and "cleanup" in r.message.lower() for r in caplog.records)
