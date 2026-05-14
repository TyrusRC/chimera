"""Regression test for A13 — `loop.create_task(broadcast_progress(...))` must hold
a strong reference so the event loop's WeakSet doesn't GC the task mid-flight.

If the broadcast task gets GC'd before it completes, asyncio emits a
`RuntimeWarning: coroutine '...' was never awaited`. We promote that warning
to an error and call `update_progress` repeatedly to surface it.
"""
from __future__ import annotations

import asyncio
import warnings

import pytest


@pytest.mark.asyncio
async def test_rapid_update_progress_does_not_leak_broadcast_tasks():
    from chimera.api.websocket import analysis as mod

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        for i in range(100):
            mod.update_progress("p-ref-test", phase=f"p{i}", detail=str(i), percent=i)

    # Let the scheduled broadcasts run so the strong-ref set drains.
    for _ in range(5):
        await asyncio.sleep(0)
    assert mod._BROADCAST_TASKS == set() or all(t.done() for t in mod._BROADCAST_TASKS)
