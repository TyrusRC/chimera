"""Opt-in, best-effort durable persistence for analyzed project models.

Off by default (`CHIMERA_PERSIST` unset): the in-memory project store stays the
source of truth and behavior is unchanged. When enabled AND a Postgres DB is
reachable, an analyzed model is *written through* so it survives a restart.

Every DB interaction is best-effort — any failure (no asyncpg, DB down, schema
mismatch) is logged once and degrades to the in-memory path; it never surfaces
to a request. DB imports are deferred so this module imports without asyncpg.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def persistence_enabled() -> bool:
    return os.environ.get("CHIMERA_PERSIST", "").strip().lower() not in ("", "0", "false", "no")


class ProjectPersistence:
    """Best-effort model save/load. Inject `db_factory` (async → DAL) for tests."""

    def __init__(self, db_factory=None) -> None:
        self._db_factory = db_factory
        self._db = None
        self._init_failed = False

    async def _get_db(self):
        if self._db is not None or self._init_failed:
            return self._db
        try:
            if self._db_factory is not None:
                self._db = await self._db_factory()
            else:
                self._db = await _default_db()
        except Exception as exc:  # noqa: BLE001 — degrade to in-memory
            logger.warning("persistence disabled — DB init failed: %s", exc)
            self._init_failed = True
            return None
        return self._db

    async def save_model(self, model) -> bool:
        """Persist a model. Returns True on success, False if skipped/failed."""
        if not persistence_enabled():
            return False
        db = await self._get_db()
        if db is None:
            return False
        try:
            await db.save_model(model)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("persistence save failed for %s: %s",
                           getattr(model.binary, "sha256", "?")[:12], exc)
            return False

    async def load_model(self, sha256: str):
        """Rehydrate a model from the DB, or None when disabled/absent/failed."""
        if not persistence_enabled():
            return None
        db = await self._get_db()
        if db is None:
            return None
        try:
            return await db.load_model_by_id(sha256)
        except Exception as exc:  # noqa: BLE001
            logger.warning("persistence load failed for %s: %s", sha256[:12], exc)
            return None


async def _default_db():
    """Build a ChimeraDatabase from the configured DSN (deferred imports)."""
    from chimera.core.config import ChimeraConfig
    from chimera.model.database import ChimeraDatabase
    from chimera.model.pool import ConnectionPool

    pool = ConnectionPool(dsn=ChimeraConfig().db_url)
    await pool.connect()
    db = ChimeraDatabase(pool=pool)
    await db.initialize()
    return db


_INSTANCE: ProjectPersistence | None = None


def get_persistence() -> ProjectPersistence:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = ProjectPersistence()
    return _INSTANCE


def reset_persistence() -> None:
    """Test isolation only."""
    global _INSTANCE
    _INSTANCE = None
