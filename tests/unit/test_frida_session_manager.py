"""Behavior tests for FridaSessionManager.

The tests inject a FakeFrida via monkeypatch on the private _attach_real /
_spawn_real / _get_device_real helpers so we don't need a real device or the
real frida binding installed.
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from chimera.api.frida_session_manager import FridaSessionManager


class FakeScript:
    def __init__(self, source: str):
        self.source = source
        self._on_message = None
        self.exports_sync = self  # so calls like script.exports_sync.eval(code) work
        self.loaded = False
        self.unloaded = False
        self._eval_return = "ok"

    def on(self, event: str, handler):
        if event == "message":
            self._on_message = handler

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True

    def eval(self, code: str) -> str:
        # Simulate the REPL script's rpc.exports.eval — and trigger a 'send' event
        # so subscribers see something flow through.
        if self._on_message:
            self._on_message({"type": "send", "payload": f"eval:{code}"}, None)
        return self._eval_return


class FakeFridaSession:
    def __init__(self):
        self.created_scripts: list[FakeScript] = []
        self.detached = False

    def create_script(self, source: str) -> FakeScript:
        s = FakeScript(source)
        self.created_scripts.append(s)
        return s

    def detach(self):
        self.detached = True


@dataclass
class FakeDevice:
    id: str = "emulator-5554"
    spawned_pid: int = 1234
    resumed: bool = False

    def attach(self, target):  # target may be package or pid
        return FakeFridaSession()

    def spawn(self, argv):
        return self.spawned_pid

    def resume(self, pid):
        self.resumed = True


@pytest.fixture
def mgr(monkeypatch):
    m = FridaSessionManager()
    monkeypatch.setattr(m, "_get_device_real", lambda device_id: FakeDevice(id=device_id or "emulator-5554"))
    return m


@pytest.mark.asyncio
async def test_create_session_attach_returns_id(mgr):
    sid = await mgr.create_session(device_id="emulator-5554", target="com.example.app", mode="attach")
    assert isinstance(sid, str) and len(sid) > 0
    assert sid in mgr.list_session_ids()


@pytest.mark.asyncio
async def test_create_session_spawn_resumes_target(mgr):
    sid = await mgr.create_session(device_id="emulator-5554", target="com.example.app", mode="spawn")
    rec = mgr.get(sid)
    assert rec.target == "com.example.app"
    assert rec.mode == "spawn"
    # Spawn must call resume() on the device after attach completes
    assert rec._device.resumed is True


@pytest.mark.asyncio
async def test_eval_returns_repl_result(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    out = await mgr.eval_code(sid, "1+1")
    assert out == "ok"  # FakeScript.eval returns "ok" by default


@pytest.mark.asyncio
async def test_eval_emits_message_to_queue(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    queue = mgr.subscribe(sid)
    await mgr.eval_code(sid, "Java.use('java.lang.String')")
    # The FakeScript fires an on_message with type=send; the manager should
    # have pushed it to the per-session queue.
    msg = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert msg["type"] == "send"
    assert "eval:" in msg["payload"]


@pytest.mark.asyncio
async def test_load_script_runs_source(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    await mgr.load_script(sid, "console.log('hello');")
    rec = mgr.get(sid)
    # The REPL bootstrap (loaded by create_session) is script #1; the user-loaded
    # script is #2. Both must be marked loaded.
    assert len(rec._scripts) == 2
    assert all(s.loaded for s in rec._scripts)


@pytest.mark.asyncio
async def test_load_bundled_script_by_id(mgr):
    """load_bundled_script reads source from chimera.frida_scripts and runs it."""
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    # Pick whichever script id is currently first in the registry. We just need
    # to confirm the manager can route to read_source() and load it.
    import chimera.frida_scripts as fs
    available = fs.list_scripts()
    if not available:
        pytest.skip("no bundled scripts available")
    target_id = available[0].id
    await mgr.load_bundled_script(sid, target_id)
    rec = mgr.get(sid)
    # The REPL is script #1; bundled script is #2.
    assert len(rec._scripts) == 2


@pytest.mark.asyncio
async def test_load_bundled_script_unknown_raises(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    with pytest.raises(KeyError):
        await mgr.load_bundled_script(sid, "no-such-script-id-xyz")


@pytest.mark.asyncio
async def test_close_session_detaches_and_unloads(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)
    await mgr.close_session(sid)
    assert rec._session.detached is True
    assert all(s.unloaded for s in rec._scripts)
    assert len(rec._scripts) >= 1  # at least the REPL bootstrap
    assert sid not in mgr.list_session_ids()


@pytest.mark.asyncio
async def test_get_unknown_session_returns_none(mgr):
    assert mgr.get("nonexistent") is None


@pytest.mark.asyncio
async def test_eval_unknown_session_raises(mgr):
    with pytest.raises(KeyError):
        await mgr.eval_code("nonexistent", "1+1")


def test_singleton_returns_same_instance():
    from chimera.api.frida_session_manager import get_session_manager
    a = get_session_manager()
    b = get_session_manager()
    assert a is b


@pytest.mark.asyncio
async def test_enqueue_from_other_thread_reaches_queue(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)
    queue = mgr.subscribe(sid)

    def push_from_thread():
        mgr._enqueue(rec, {"type": "send", "payload": "from-other-thread"})

    t = threading.Thread(target=push_from_thread)
    t.start()
    t.join()
    msg = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert msg["payload"] == "from-other-thread"


@pytest.mark.asyncio
async def test_eval_does_not_block_event_loop(mgr, monkeypatch):
    """A slow rpc.exports.eval must not stall the event loop."""
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)

    # Make eval block for 0.4s of real time (simulating a frozen target).
    import time
    rec._repl_script._eval_return = "slow"
    original_eval = rec._repl_script.eval
    def slow_eval(code):
        time.sleep(0.4)
        return original_eval(code)
    rec._repl_script.eval = slow_eval

    # While eval runs, a parallel asyncio.sleep(0.05) must finish well before eval does.
    async def parallel_marker():
        await asyncio.sleep(0.05)
        return "fast-path-ran"

    eval_task = asyncio.create_task(mgr.eval_code(sid, "1+1"))
    marker_task = asyncio.create_task(parallel_marker())
    done, _ = await asyncio.wait({eval_task, marker_task}, return_when=asyncio.FIRST_COMPLETED)
    # The marker must finish first; if the loop is blocked, eval finishes first.
    assert marker_task in done
    assert marker_task.result() == "fast-path-ran"
    await eval_task  # drain


@pytest.mark.asyncio
async def test_subscribe_fanout_two_subscribers_both_see_messages(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)
    q1 = mgr.subscribe(sid)
    q2 = mgr.subscribe(sid)
    mgr._enqueue(rec, {"type": "send", "payload": "hello"})
    m1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    m2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert m1["payload"] == "hello"
    assert m2["payload"] == "hello"


@pytest.mark.asyncio
async def test_unsubscribe_removes_queue_from_fanout(mgr):
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)
    q1 = mgr.subscribe(sid)
    q2 = mgr.subscribe(sid)
    mgr.unsubscribe(sid, q2)
    mgr._enqueue(rec, {"type": "send", "payload": "after"})
    m1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    assert m1["payload"] == "after"
    assert q2.qsize() == 0  # q2 was unsubscribed before _enqueue


@pytest.mark.asyncio
async def test_enqueue_with_no_subscribers_does_not_grow_unbounded(mgr):
    """When no subscriber is attached, _enqueue must be a no-op (or bounded)."""
    sid = await mgr.create_session(device_id=None, target="com.example.app", mode="attach")
    rec = mgr.get(sid)
    for _ in range(5000):
        mgr._enqueue(rec, {"type": "send", "payload": "drop"})
    # No subscribers, so no queue should be growing. The record itself shouldn't
    # hold an unbounded buffer either.
    assert getattr(rec, "_subscribers", []) == []
