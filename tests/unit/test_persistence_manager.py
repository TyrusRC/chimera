"""H2: opt-in, best-effort durable persistence manager.

The DB execution path is Postgres (integration suite). Here we verify the
manager's contract without asyncpg: it's off unless CHIMERA_PERSIST is set,
it delegates to the DAL when on, and any DB error degrades silently.
"""

from __future__ import annotations

import asyncio

import pytest

from chimera.api.persistence import ProjectPersistence, persistence_enabled


class _FakeDB:
    def __init__(self, *, raises=False):
        self.raises = raises
        self.saved = []
        self.loaded = []

    async def save_model(self, model):
        if self.raises:
            raise RuntimeError("db down")
        self.saved.append(model)

    async def load_model_by_id(self, ident):
        if self.raises:
            raise RuntimeError("db down")
        self.loaded.append(ident)
        return {"model": ident}  # stand-in


def _mgr(db):
    return ProjectPersistence(db_factory=lambda: _async(db))


async def _async(v):
    return v


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CHIMERA_PERSIST", raising=False)
    assert persistence_enabled() is False
    db = _FakeDB()
    mgr = _mgr(db)
    assert asyncio.run(mgr.save_model(object())) is False
    assert asyncio.run(mgr.load_model("abc")) is None
    assert db.saved == [] and db.loaded == []  # DB never touched


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_enabled_values(monkeypatch, val):
    monkeypatch.setenv("CHIMERA_PERSIST", val)
    assert persistence_enabled() is True


def test_save_and_load_when_enabled(monkeypatch):
    monkeypatch.setenv("CHIMERA_PERSIST", "1")
    db = _FakeDB()
    mgr = _mgr(db)
    model = type("M", (), {"binary": type("B", (), {"sha256": "f" * 64})()})()
    assert asyncio.run(mgr.save_model(model)) is True
    assert db.saved == [model]
    assert asyncio.run(mgr.load_model("deadbeef")) == {"model": "deadbeef"}
    assert db.loaded == ["deadbeef"]


def test_best_effort_swallows_db_errors(monkeypatch):
    monkeypatch.setenv("CHIMERA_PERSIST", "1")
    db = _FakeDB(raises=True)
    mgr = _mgr(db)
    model = type("M", (), {"binary": type("B", (), {"sha256": "f" * 64})()})()
    # Must not raise; returns False/None on DB failure.
    assert asyncio.run(mgr.save_model(model)) is False
    assert asyncio.run(mgr.load_model("abc")) is None


def test_db_init_failure_degrades(monkeypatch):
    monkeypatch.setenv("CHIMERA_PERSIST", "1")

    async def _boom():
        raise RuntimeError("no asyncpg")

    mgr = ProjectPersistence(db_factory=_boom)
    assert asyncio.run(mgr.save_model(object())) is False
    assert asyncio.run(mgr.load_model("abc")) is None
