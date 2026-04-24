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


async def test_pool_connect_times_out_when_dsn_is_dead(monkeypatch):
    from chimera.model.pool import ConnectionPool, PoolInitError

    async def slow_create_pool(**kw):
        import asyncio
        await asyncio.sleep(10)

    import asyncpg
    monkeypatch.setattr(asyncpg, "create_pool", slow_create_pool)

    p = ConnectionPool("postgres://dead:1/x", timeout=0.2)
    import pytest
    with pytest.raises(PoolInitError):
        await p.connect()
