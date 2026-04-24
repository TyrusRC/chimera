"""PostgreSQL persistence layer for the Unified Program Model."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from chimera.model.binary import (
    Architecture,
    BinaryFormat,
    BinaryInfo,
    Framework,
    Platform,
)
from chimera.model.function import FunctionInfo
from chimera.model.pool import ConnectionPool
from chimera.model.schema import PROJECT_SCHEMA


class ChimeraDatabase:
    """Project data access layer. All calls go through a shared pool."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    async def initialize(self) -> None:
        """Apply schema DDL (idempotent)."""
        async with self._pool.acquire() as conn:
            await conn.execute(PROJECT_SCHEMA)

    async def list_tables(self) -> list[str]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public'"
            )
        return [r["tablename"] for r in rows]

    async def save_binary(self, binary: BinaryInfo) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO binaries
                    (sha256, path, format, platform, arch, framework,
                     size_bytes, package_name, version, min_sdk)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (sha256) DO UPDATE SET
                    path = EXCLUDED.path,
                    format = EXCLUDED.format,
                    platform = EXCLUDED.platform,
                    arch = EXCLUDED.arch,
                    framework = EXCLUDED.framework,
                    size_bytes = EXCLUDED.size_bytes,
                    package_name = EXCLUDED.package_name,
                    version = EXCLUDED.version,
                    min_sdk = EXCLUDED.min_sdk,
                    analyzed_at = NOW(),
                    analysis_version = binaries.analysis_version + 1
                """,
                binary.sha256,
                str(binary.path),
                binary.format.value,
                binary.platform.value,
                binary.arch.value,
                binary.framework.value,
                binary.size_bytes,
                binary.package_name,
                binary.version,
                binary.min_sdk,
            )

    async def load_binary(self, sha256: str) -> Optional[BinaryInfo]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT sha256, path, format, platform, arch, framework,
                       size_bytes, package_name, version, min_sdk
                FROM binaries WHERE sha256 = $1
                """,
                sha256,
            )
        if row is None:
            return None
        return BinaryInfo(
            sha256=row["sha256"],
            path=Path(row["path"]),
            format=BinaryFormat(row["format"]),
            platform=Platform(row["platform"]),
            arch=Architecture(row["arch"]),
            framework=Framework(row["framework"]),
            size_bytes=row["size_bytes"],
            package_name=row["package_name"],
            version=row["version"],
            min_sdk=row["min_sdk"],
        )

    async def binary_exists(self, sha256: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT 1 FROM binaries WHERE sha256 = $1", sha256
            )
        return result is not None

    # TODO(sub-project-followup): persist FunctionInfo.sources column.
    # Currently merge-history is dropped on save/load round-trip.
    async def save_function(
        self, binary_sha256: str, func: FunctionInfo
    ) -> None:
        if func.sources:
            import logging
            logging.getLogger(__name__).warning(
                "save_function: FunctionInfo.sources=%r will be dropped - "
                "column not yet persisted (follow-up sub-project)",
                func.sources,
            )
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO functions
                    (binary_sha256, address, name, original_name, language,
                     classification, layer, source_backend, decompiled,
                     signature, ai_renamed, ai_comments)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (binary_sha256, address) DO UPDATE SET
                    name = EXCLUDED.name,
                    original_name = EXCLUDED.original_name,
                    language = EXCLUDED.language,
                    classification = EXCLUDED.classification,
                    layer = EXCLUDED.layer,
                    source_backend = EXCLUDED.source_backend,
                    decompiled = EXCLUDED.decompiled,
                    signature = EXCLUDED.signature,
                    ai_renamed = EXCLUDED.ai_renamed,
                    ai_comments = EXCLUDED.ai_comments
                """,
                binary_sha256,
                func.address,
                func.name,
                func.original_name,
                func.language,
                func.classification,
                func.layer,
                func.source_backend,
                func.decompiled,
                func.signature,
                func.ai_renamed,
                func.ai_comments,
            )

    # TODO(sub-project-followup): persist FunctionInfo.sources column.
    # Currently merge-history is dropped on save/load round-trip.
    async def load_functions(
        self, binary_sha256: str
    ) -> list[FunctionInfo]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT address, name, original_name, language, classification,
                       layer, source_backend, decompiled, signature,
                       ai_renamed, ai_comments
                FROM functions WHERE binary_sha256 = $1
                ORDER BY address
                """,
                binary_sha256,
            )
        return [
            FunctionInfo(
                address=r["address"],
                name=r["name"],
                original_name=r["original_name"],
                language=r["language"],
                classification=r["classification"],
                layer=r["layer"],
                source_backend=r["source_backend"],
                decompiled=r["decompiled"],
                signature=r["signature"],
                ai_renamed=r["ai_renamed"],
                ai_comments=r["ai_comments"],
            )
            for r in rows
        ]
