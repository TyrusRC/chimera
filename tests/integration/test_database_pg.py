"""Parity tests for ChimeraDatabase (postgres backend).

Mirrors the pre-migration tests/unit/test_database.py contracts. Passing
means the asyncpg rewrite is API-compatible with the aiosqlite version
it replaced.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

from chimera.model.binary import (
    Architecture,
    BinaryFormat,
    BinaryInfo,
    Framework,
    Platform,
)
from chimera.model.database import ChimeraDatabase
from chimera.model.function import FunctionInfo


@pytest_asyncio.fixture(loop_scope="session")
async def db(pg_clean):
    database = ChimeraDatabase(pool=pg_clean)
    await database.initialize()
    yield database


def _make_binary() -> BinaryInfo:
    return BinaryInfo(
        sha256="a" * 64,
        path=Path("/tmp/test.apk"),
        format=BinaryFormat.APK,
        platform=Platform.ANDROID,
        arch=Architecture.DEX,
        framework=Framework.NATIVE,
        size_bytes=1024,
    )


@pytest.mark.asyncio(loop_scope="session")
class TestDatabasePg:
    async def test_initialize_creates_tables(self, db):
        tables = await db.list_tables()
        assert "binaries" in tables
        assert "functions" in tables
        assert "strings" in tables

    async def test_save_and_load_binary(self, db):
        await db.save_binary(_make_binary())
        loaded = await db.load_binary("a" * 64)
        assert loaded is not None
        assert loaded.sha256 == "a" * 64
        assert loaded.format == BinaryFormat.APK

    async def test_load_missing_binary_returns_none(self, db):
        assert await db.load_binary("nonexistent") is None

    async def test_save_and_load_function(self, db):
        binary = _make_binary()
        await db.save_binary(binary)
        func = FunctionInfo(
            address="0x1000",
            name="main",
            original_name="FUN_1000",
            language="java",
            classification="init",
            layer="java",
            source_backend="jadx",
            ai_renamed=True,
            ai_comments="hand-inspected",
        )
        await db.save_function(binary.sha256, func)
        functions = await db.load_functions(binary.sha256)
        assert len(functions) == 1
        loaded = functions[0]
        assert loaded.name == "main"
        # These fields use non-default types (BOOLEAN, nullable TEXT) —
        # round-tripping catches codec regressions.
        assert loaded.ai_renamed is True
        assert loaded.ai_comments == "hand-inspected"

    async def test_binary_exists(self, db):
        binary = _make_binary()
        assert await db.binary_exists("a" * 64) is False
        await db.save_binary(binary)
        assert await db.binary_exists("a" * 64) is True

    async def test_save_binary_is_upsert(self, db):
        import dataclasses

        original = _make_binary()
        await db.save_binary(original)
        # Same sha256 but different size_bytes — ON CONFLICT DO UPDATE
        # must overwrite the row, not silently discard the new data.
        mutated = dataclasses.replace(original, size_bytes=9999)
        await db.save_binary(mutated)
        loaded = await db.load_binary("a" * 64)
        assert loaded is not None
        assert loaded.size_bytes == 9999, \
            "upsert must overwrite existing columns, not DO NOTHING"
