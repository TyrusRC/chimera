import pytest
from pathlib import Path
from chimera.model.database import ChimeraDatabase
from chimera.model.binary import BinaryInfo, BinaryFormat, Platform, Architecture, Framework
from chimera.model.function import FunctionInfo


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    database = ChimeraDatabase(db_path)
    await database.initialize()
    yield database
    await database.close()


def _make_binary():
    return BinaryInfo(
        sha256="a" * 64, path=Path("/tmp/test.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.DEX, framework=Framework.NATIVE, size_bytes=1024,
    )


class TestDatabase:
    async def test_initialize_creates_tables(self, db):
        tables = await db.list_tables()
        assert "binaries" in tables
        assert "functions" in tables
        assert "strings" in tables
        assert "findings" in tables

    async def test_save_and_load_binary(self, db):
        binary = _make_binary()
        await db.save_binary(binary)
        loaded = await db.load_binary("a" * 64)
        assert loaded is not None
        assert loaded.sha256 == "a" * 64
        assert loaded.format == BinaryFormat.APK

    async def test_load_missing_binary_returns_none(self, db):
        result = await db.load_binary("nonexistent")
        assert result is None

    async def test_save_and_load_function(self, db):
        binary = _make_binary()
        await db.save_binary(binary)
        func = FunctionInfo(
            address="0x1000", name="main", original_name="FUN_1000",
            language="java", classification="init", layer="java", source_backend="jadx",
        )
        await db.save_function(binary.sha256, func)
        functions = await db.load_functions(binary.sha256)
        assert len(functions) == 1
        assert functions[0].name == "main"

    async def test_binary_exists(self, db):
        binary = _make_binary()
        assert await db.binary_exists("a" * 64) is False
        await db.save_binary(binary)
        assert await db.binary_exists("a" * 64) is True
