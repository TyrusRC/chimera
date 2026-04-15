"""SQLite persistence layer for the Unified Program Model."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import aiosqlite

from chimera.model.binary import BinaryInfo, BinaryFormat, Platform, Architecture, Framework
from chimera.model.function import FunctionInfo

SCHEMA = """
CREATE TABLE IF NOT EXISTS binaries (
    sha256 TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    format TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    framework TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    package_name TEXT,
    version TEXT,
    min_sdk INTEGER,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    address TEXT NOT NULL,
    name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    language TEXT NOT NULL,
    classification TEXT NOT NULL,
    layer TEXT NOT NULL,
    source_backend TEXT NOT NULL,
    decompiled TEXT,
    signature TEXT,
    ai_renamed BOOLEAN DEFAULT FALSE,
    ai_comments TEXT,
    UNIQUE(binary_sha256, address)
);

CREATE TABLE IF NOT EXISTS call_graph (
    caller_binary TEXT NOT NULL,
    caller_addr TEXT NOT NULL,
    callee_addr TEXT NOT NULL,
    call_type TEXT NOT NULL DEFAULT 'direct',
    PRIMARY KEY (caller_binary, caller_addr, callee_addr)
);

CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    address TEXT NOT NULL,
    value TEXT NOT NULL,
    section TEXT,
    decrypted_from TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unverified',
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT NOT NULL,
    description TEXT,
    location TEXT,
    evidence_static TEXT,
    evidence_dynamic TEXT,
    masvs_category TEXT,
    mastg_test TEXT,
    business_impact TEXT,
    poc TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    confirmed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    permission TEXT NOT NULL,
    declared BOOLEAN DEFAULT TRUE,
    actually_used BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (binary_sha256, permission)
);

CREATE TABLE IF NOT EXISTS protections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    type TEXT NOT NULL,
    product TEXT,
    bypassed BOOLEAN DEFAULT FALSE,
    bypass_method TEXT
);

CREATE TABLE IF NOT EXISTS sdks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
    name TEXT NOT NULL,
    version TEXT,
    package_prefix TEXT,
    risk_level TEXT DEFAULT 'clean',
    known_cves TEXT
);
"""


class ChimeraDatabase:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    async def list_tables(self) -> list[str]:
        cursor = await self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]

    async def save_binary(self, binary: BinaryInfo) -> None:
        await self._conn.execute(
            """INSERT OR REPLACE INTO binaries
               (sha256, path, format, platform, arch, framework, size_bytes, package_name, version, min_sdk)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (binary.sha256, str(binary.path), binary.format.value, binary.platform.value,
             binary.arch.value, binary.framework.value, binary.size_bytes,
             binary.package_name, binary.version, binary.min_sdk),
        )
        await self._conn.commit()

    async def load_binary(self, sha256: str) -> Optional[BinaryInfo]:
        cursor = await self._conn.execute(
            "SELECT sha256, path, format, platform, arch, framework, size_bytes, package_name, version, min_sdk "
            "FROM binaries WHERE sha256 = ?", (sha256,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return BinaryInfo(
            sha256=row[0], path=Path(row[1]), format=BinaryFormat(row[2]),
            platform=Platform(row[3]), arch=Architecture(row[4]),
            framework=Framework(row[5]), size_bytes=row[6],
            package_name=row[7], version=row[8], min_sdk=row[9],
        )

    async def binary_exists(self, sha256: str) -> bool:
        cursor = await self._conn.execute(
            "SELECT 1 FROM binaries WHERE sha256 = ?", (sha256,)
        )
        return await cursor.fetchone() is not None

    async def save_function(self, binary_sha256: str, func: FunctionInfo) -> None:
        await self._conn.execute(
            """INSERT OR REPLACE INTO functions
               (binary_sha256, address, name, original_name, language,
                classification, layer, source_backend, decompiled, signature,
                ai_renamed, ai_comments)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (binary_sha256, func.address, func.name, func.original_name,
             func.language, func.classification, func.layer, func.source_backend,
             func.decompiled, func.signature, func.ai_renamed, func.ai_comments),
        )
        await self._conn.commit()

    async def load_functions(self, binary_sha256: str) -> list[FunctionInfo]:
        cursor = await self._conn.execute(
            """SELECT address, name, original_name, language, classification,
                      layer, source_backend, decompiled, signature, ai_renamed, ai_comments
               FROM functions WHERE binary_sha256 = ?""", (binary_sha256,),
        )
        rows = await cursor.fetchall()
        return [
            FunctionInfo(
                address=r[0], name=r[1], original_name=r[2], language=r[3],
                classification=r[4], layer=r[5], source_backend=r[6],
                decompiled=r[7], signature=r[8], ai_renamed=bool(r[9]), ai_comments=r[10],
            )
            for r in rows
        ]
