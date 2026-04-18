"""Unit tests for the asyncpg connection pool factory."""

import pytest

from chimera.model.pool import ConnectionPool


async def test_pool_requires_dsn():
    with pytest.raises(ValueError, match="dsn is required"):
        ConnectionPool(dsn="")


async def test_pool_min_size_default():
    pool = ConnectionPool(dsn="postgresql://x:y@localhost/z")
    assert pool.min_size == 2
    assert pool.max_size == 10


async def test_pool_custom_sizes():
    pool = ConnectionPool(dsn="postgresql://x:y@localhost/z", min_size=1, max_size=5)
    assert pool.min_size == 1
    assert pool.max_size == 5


async def test_pool_not_connected_raises_on_acquire():
    pool = ConnectionPool(dsn="postgresql://x:y@localhost/z")
    with pytest.raises(RuntimeError, match="not connected"):
        async with pool.acquire():
            pass
