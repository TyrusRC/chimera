"""Async PostgreSQL connection pool factory."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import asyncpg


class PoolInitError(RuntimeError):
    """Raised when `ConnectionPool.connect()` cannot establish a pool in time."""


class ConnectionPool:
    """Wrapper around asyncpg.Pool with explicit connect/disconnect lifecycle."""

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 2,
        max_size: int = 10,
        command_timeout: float = 60.0,
        timeout: float = 10.0,
    ) -> None:
        if not dsn:
            raise ValueError("dsn is required")
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self.command_timeout = command_timeout
        self.timeout = timeout
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        try:
            pool = await asyncio.wait_for(
                asyncpg.create_pool(
                    dsn=self.dsn,
                    min_size=self.min_size,
                    max_size=self.max_size,
                    command_timeout=self.command_timeout,
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError as exc:
            raise PoolInitError(
                f"pool connect timed out after {self.timeout}s"
            ) from exc
        if pool is None:
            raise PoolInitError(
                "asyncpg.create_pool returned None; check DSN and server availability"
            )
        self._pool = pool

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
