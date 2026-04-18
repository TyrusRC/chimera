"""Async PostgreSQL connection pool factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import asyncpg


class ConnectionPool:
    """Wrapper around asyncpg.Pool with explicit connect/disconnect lifecycle."""

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 2,
        max_size: int = 10,
        command_timeout: float = 60.0,
    ) -> None:
        if not dsn:
            raise ValueError("dsn is required")
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self.command_timeout = command_timeout
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self.min_size,
            max_size=self.max_size,
            command_timeout=self.command_timeout,
        )

    async def disconnect(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[asyncpg.Connection]:
        if self._pool is None:
            raise RuntimeError("pool is not connected; call connect() first")
        async with self._pool.acquire() as conn:
            yield conn
