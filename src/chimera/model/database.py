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
from chimera.model.serialize import decode_sources, encode_sources


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

    async def save_strings(self, binary_sha256: str, model) -> None:
        """Replace the persisted strings for a binary (idempotent re-save)."""
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM strings WHERE binary_sha256 = $1", binary_sha256)
            for s in model.get_strings():
                await conn.execute(
                    """
                    INSERT INTO strings (binary_sha256, address, value, section, decrypted_from)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    binary_sha256, s.address, s.value, s.section, s.decrypted_from,
                )

    async def load_strings(self, binary_sha256: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT address, value, section, decrypted_from "
                "FROM strings WHERE binary_sha256 = $1", binary_sha256,
            )
        return [dict(r) for r in rows]

    async def save_call_edges(self, binary_sha256: str, model) -> None:
        """Replace the persisted call graph for a binary (idempotent re-save)."""
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM call_graph WHERE caller_binary = $1", binary_sha256)
            for e in model.call_edges:
                await conn.execute(
                    """
                    INSERT INTO call_graph (caller_binary, caller_addr, callee_addr, call_type)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (caller_binary, caller_addr, callee_addr) DO NOTHING
                    """,
                    binary_sha256, e.caller_addr, e.callee_addr, e.call_type,
                )

    async def load_call_edges(self, binary_sha256: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT caller_addr, callee_addr, call_type "
                "FROM call_graph WHERE caller_binary = $1", binary_sha256,
            )
        return [dict(r) for r in rows]

    async def save_model(self, model) -> None:
        """Persist a UnifiedProgramModel: binary + functions + strings + call graph."""
        await self.save_binary(model.binary)
        for func in model.functions:
            await self.save_function(model.binary.sha256, func)
        await self.save_strings(model.binary.sha256, model)
        await self.save_call_edges(model.binary.sha256, model)

    async def load_model(self, sha256: str):
        """Rehydrate a full UnifiedProgramModel from the durable store, or None."""
        from chimera.model.program import UnifiedProgramModel

        binary = await self.load_binary(sha256)
        if binary is None:
            return None
        model = UnifiedProgramModel(binary)
        for func in await self.load_functions(sha256):
            model.add_function(func)
        for s in await self.load_strings(sha256):
            model.add_string(s["address"], s["value"], section=s["section"],
                             decrypted_from=s["decrypted_from"])
        for e in await self.load_call_edges(sha256):
            model.add_call_edge(e["caller_addr"], e["callee_addr"], e["call_type"])
        return model

    async def load_model_by_id(self, ident: str):
        """Load a model by full sha256 (64 chars) or a project-id prefix."""
        if len(ident) == 64:
            return await self.load_model(ident)
        async with self._pool.acquire() as conn:
            sha = await conn.fetchval(
                "SELECT sha256 FROM binaries WHERE sha256 LIKE $1 LIMIT 1",
                ident + "%",
            )
        if not sha:
            return None
        return await self.load_model(sha)

    async def binary_exists(self, sha256: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT 1 FROM binaries WHERE sha256 = $1", sha256
            )
        return result is not None

    async def save_function(
        self, binary_sha256: str, func: FunctionInfo
    ) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO functions
                    (binary_sha256, address, name, original_name, language,
                     classification, layer, source_backend, decompiled,
                     signature, ai_renamed, ai_comments, sources)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
                    ai_comments = EXCLUDED.ai_comments,
                    sources = EXCLUDED.sources
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
                encode_sources(func.sources),
            )

    async def load_functions(
        self, binary_sha256: str
    ) -> list[FunctionInfo]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT address, name, original_name, language, classification,
                       layer, source_backend, decompiled, signature,
                       ai_renamed, ai_comments, sources
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
                sources=decode_sources(r["sources"]),
            )
            for r in rows
        ]
