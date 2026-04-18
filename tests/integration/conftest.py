"""Shared fixtures for integration tests.

Spins up an ephemeral PostgreSQL 16 container for the duration of the test
session. Schema is applied once, then each test runs after a TRUNCATE so
tests do not see each other's data.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer

from chimera.model.pool import ConnectionPool
from chimera.model.schema import PROJECT_SCHEMA, PROJECT_TABLES


@pytest.fixture(scope="session")
def pg_container():
    container = PostgresContainer(
        "postgres:16",
        username="chimera",
        password="chimera",
        dbname="chimera_projects",
    )
    container.start()
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def pg_dsn(pg_container) -> str:
    # testcontainers returns a SQLAlchemy URL with a driver qualifier like
    # postgresql+psycopg2:// or postgresql+asyncpg://. asyncpg wants a bare
    # postgresql:// URL, so strip any +<driver> segment regardless of name.
    raw = pg_container.get_connection_url()
    return re.sub(r"^postgresql\+[^:]+://", "postgresql://", raw)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def pg_pool(pg_dsn) -> AsyncIterator[ConnectionPool]:
    # Install required extensions + schema once per session.
    pool = ConnectionPool(dsn=pg_dsn, min_size=1, max_size=5)
    await pool.connect()
    async with pool.acquire() as conn:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
        await conn.execute("CREATE EXTENSION IF NOT EXISTS btree_gin;")
        await conn.execute(PROJECT_SCHEMA)
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture(loop_scope="session")
async def pg_clean(pg_pool) -> AsyncIterator[ConnectionPool]:
    # Truncate project tables before each test so tests are isolated.
    # CASCADE handles FK order; RESTART IDENTITY resets sequences.
    table_list = ", ".join(PROJECT_TABLES)
    async with pg_pool.acquire() as conn:
        await conn.execute(
            f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE;"
        )
    yield pg_pool
