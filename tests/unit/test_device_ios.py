from chimera.device.ios import IOSDeviceManager


class TestIOSDeviceManager:
    def test_name(self):
        assert IOSDeviceManager().name == "ios"

    def test_is_available_checks_tools(self):
        _ = IOSDeviceManager().is_available

    async def test_cleanup(self):
        await IOSDeviceManager().cleanup()


async def test_iproxy_health_check_detects_dead_proc(monkeypatch):
    """iproxy_alive() must reflect the subprocess returncode so callers can
    detect silent iproxy crashes mid-analysis."""
    from chimera.device.ios import IOSDeviceManager

    mgr = IOSDeviceManager()

    class FakeProc:
        # _rc consumed in order:
        #   1st pop: forward_port's `proc.returncode is None` check → None (alive, stash)
        #   2nd pop: first iproxy_alive() call → None (still alive)
        #   3rd pop: second iproxy_alive() call → 1 (dead)
        #   tail: 1 (stays dead on any further access)
        _rc = [None, None, 1, 1]

        @property
        def returncode(self):
            return self._rc.pop(0) if self._rc else 1

        def terminate(self):
            pass

    async def fake_exec(*a, **kw):
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    ok = await mgr.forward_port("D", 27042, 27042)
    assert ok is True
    # first health check: alive
    assert mgr.iproxy_alive() is True
    # second health check: dead
    assert mgr.iproxy_alive() is False


async def test_ios_is_alive_false_when_ideviceid_missing(monkeypatch):
    from chimera.device.ios import IOSDeviceManager
    mgr = IOSDeviceManager()

    async def fail(self_arg, *a, **kw):
        raise RuntimeError("no idevice_id")
    monkeypatch.setattr(IOSDeviceManager, "_run", fail)
    assert (await mgr.is_alive("D")) is False


async def test_ios_is_alive_true_when_udid_listed(monkeypatch):
    from chimera.device.ios import IOSDeviceManager
    mgr = IOSDeviceManager()

    async def ok(self_arg, *a, **kw):
        return "D\nOTHER-UDID\n"
    monkeypatch.setattr(IOSDeviceManager, "_run", ok)
    assert (await mgr.is_alive("D")) is True
