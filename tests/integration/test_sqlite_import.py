"""Migration tool: read an SQLite project DB, write to Postgres."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from chimera.migration.sqlite_import import import_sqlite_to_postgres


@pytest.fixture
def sqlite_file(tmp_path: Path) -> Path:
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE binaries (
            sha256 TEXT PRIMARY KEY, path TEXT, format TEXT, platform TEXT,
            arch TEXT, framework TEXT, size_bytes INTEGER,
            package_name TEXT, version TEXT, min_sdk INTEGER
        );
        CREATE TABLE functions (
            id INTEGER PRIMARY KEY, binary_sha256 TEXT, address TEXT,
            name TEXT, original_name TEXT, language TEXT, classification TEXT,
            layer TEXT, source_backend TEXT, decompiled TEXT, signature TEXT,
            ai_renamed INTEGER DEFAULT 0, ai_comments TEXT
        );
        CREATE TABLE strings (
            id INTEGER PRIMARY KEY, binary_sha256 TEXT, address TEXT,
            value TEXT, section TEXT, decrypted_from TEXT
        );
        INSERT INTO binaries VALUES
            ('abc123', '/tmp/x.apk', 'apk', 'android', 'dex', 'native',
             1024, 'com.x', '1.0', 21);
        INSERT INTO functions (binary_sha256, address, name, original_name,
            language, classification, layer, source_backend)
          VALUES ('abc123', '0x100', 'main', 'FUN_100', 'java', 'init',
            'java', 'jadx');
        INSERT INTO strings (binary_sha256, address, value)
          VALUES ('abc123', '0x200', 'hello');
    """)
    conn.commit()
    conn.close()
    return db


@pytest.mark.asyncio(loop_scope="session")
class TestSqliteImport:
    async def test_imports_binaries_functions_and_strings(
        self, sqlite_file: Path, pg_clean
    ) -> None:
        dsn = pg_clean.dsn
        report = await import_sqlite_to_postgres(sqlite_file, dsn)
        assert report["binaries"] == 1
        assert report["functions"] == 1
        assert report["strings"] == 1

        async with pg_clean.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT sha256, package_name FROM binaries WHERE sha256 = $1",
                "abc123",
            )
        assert row["package_name"] == "com.x"

    async def test_is_idempotent(self, sqlite_file: Path, pg_clean) -> None:
        dsn = pg_clean.dsn
        await import_sqlite_to_postgres(sqlite_file, dsn)
        await import_sqlite_to_postgres(sqlite_file, dsn)
        async with pg_clean.acquire() as conn:
            count = await conn.fetchval("SELECT count(*) FROM binaries")
        assert count == 1
