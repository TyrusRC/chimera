"""Websocket analysis broadcast behavior."""
from __future__ import annotations

import pytest


async def test_dead_websocket_is_removed_on_send_failure():
    from chimera.api.websocket import analysis as ws_mod

    # Reset module state (tests don't share by default, but be defensive)
    ws_mod._subscribers.clear()
    ws_mod._progress.clear()

    class DeadWS:
        async def send_json(self, data):
            raise RuntimeError("closed")

    class LiveWS:
        def __init__(self):
            self.received = []
        async def send_json(self, data):
            self.received.append(data)

    dead = DeadWS()
    live = LiveWS()
    ws_mod._subscribers["p1"] = [dead, live]
    ws_mod._progress["p1"] = {"percent": 50}

    await ws_mod.broadcast_progress("p1")

    # Dead ws is removed, live ws remains
    assert ws_mod._subscribers["p1"] == [live]
    assert live.received == [{"percent": 50}]


async def test_broadcast_progress_no_subscribers_is_noop():
    from chimera.api.websocket import analysis as ws_mod
    ws_mod._subscribers.clear()
    ws_mod._progress["empty"] = {"phase": "idle"}
    # Must not raise when no subscribers exist
    await ws_mod.broadcast_progress("empty")
