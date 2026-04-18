import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_pg_fixture_is_alive(pg_clean):
    async with pg_clean.acquire() as conn:
        version = await conn.fetchval("SELECT version();")
    assert "PostgreSQL 16" in version
