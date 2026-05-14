"""When a project is created, the analysis task is tracked in _ProjectStore._tasks
and is cancellable via DELETE /api/projects/{id}."""
from __future__ import annotations

import asyncio

import pytest


@pytest.mark.asyncio
async def test_register_task_stores_and_clears_on_done():
    from chimera.api.routes.projects import _ProjectStore

    store = _ProjectStore({})

    done = asyncio.Event()

    async def runner():
        await done.wait()

    task = asyncio.create_task(runner())
    store.register_task("p1", task)
    assert store.get_task("p1") is task

    done.set()
    await task
    # Done callback runs once the task is finished; yield so it fires.
    await asyncio.sleep(0)
    assert store.get_task("p1") is None


@pytest.mark.asyncio
async def test_register_task_cleared_on_cancel():
    from chimera.api.routes.projects import _ProjectStore

    store = _ProjectStore({})

    async def runner():
        await asyncio.sleep(60)

    task = asyncio.create_task(runner())
    store.register_task("p2", task)
    assert store.get_task("p2") is task

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert store.get_task("p2") is None
