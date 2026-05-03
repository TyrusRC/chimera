import pytest
from chimera.device.base import DeviceInfo, DevicePlatform
from chimera.device.android import AndroidDeviceManager


class TestDeviceInfo:
    def test_create(self):
        info = DeviceInfo(
            id="emulator-5554",
            platform=DevicePlatform.ANDROID,
            model="Pixel 6",
            os_version="14",
            arch="arm64",
            is_rooted=True,
        )
        assert info.id == "emulator-5554"
        assert info.platform == DevicePlatform.ANDROID
        assert info.is_rooted is True


class TestAndroidDeviceManager:
    def test_name(self):
        mgr = AndroidDeviceManager()
        assert mgr.name == "android"

    def test_is_available_checks_adb(self):
        mgr = AndroidDeviceManager()
        # Just verify it doesn't crash
        _ = mgr.is_available

    async def test_cleanup(self):
        mgr = AndroidDeviceManager()
        await mgr.cleanup()


async def test_adb_nonzero_exit_raises_with_stderr(monkeypatch):
    from chimera.device.android import AndroidDeviceManager, AdbError

    async def fake_exec(*args, **kw):
        class FakeProc:
            returncode = 1
            async def communicate(self):
                return b"", b"adb: device offline"
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    mgr = AndroidDeviceManager()
    import pytest
    with pytest.raises(AdbError, match="device offline"):
        await mgr._adb_argv(["devices"])


async def test_pull_app_returns_all_split_apks(tmp_path, monkeypatch):
    from chimera.device.android import AndroidDeviceManager

    mgr = AndroidDeviceManager()

    async def fake_adb_argv(device_id, argv):
        args = " ".join(argv)
        if args.startswith("shell pm path"):
            return (
                "package:/data/app/base.apk\n"
                "package:/data/app/split_config.arm64_v8a.apk\n"
            )
        if argv and argv[0] == "pull":
            src, dst = argv[1], argv[2]
            from pathlib import Path
            Path(dst).write_bytes(b"x")
        return ""

    monkeypatch.setattr(mgr, "_adb_device_argv", fake_adb_argv)

    paths = await mgr.pull_app("D", "com.x", str(tmp_path))
    assert isinstance(paths, list), f"expected list, got {type(paths)}"
    assert len(paths) == 2
    assert any("base.apk" in p for p in paths)
    assert any("split_config" in p for p in paths)


async def test_adb_device_accepts_args_with_spaces(monkeypatch):
    """Paths with spaces must not be corrupted by internal splitting."""
    from chimera.device.android import AndroidDeviceManager

    seen_args: list[tuple[str, ...]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"ok", b""

    async def fake_exec(*argv, **kw):
        seen_args.append(tuple(argv))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    mgr = AndroidDeviceManager()
    # New argv-list variant — must preserve path-with-spaces intact
    await mgr._adb_device_argv("D", ["pull", "/data/App Name/base.apk", "/tmp/out"])
    argv = seen_args[-1]
    assert "/data/App Name/base.apk" in argv
    i = argv.index("/data/App Name/base.apk")
    assert argv[i + 1] == "/tmp/out"


async def test_android_is_alive_false_when_adb_fails(monkeypatch):
    from chimera.device.android import AndroidDeviceManager, AdbError
    mgr = AndroidDeviceManager()

    async def fail(self_arg, device_id, argv):
        raise AdbError("x", 1, "offline")
    monkeypatch.setattr(AndroidDeviceManager, "_adb_device_argv", fail)
    alive = await mgr.is_alive("D")
    assert alive is False


async def test_android_is_alive_true_on_successful_echo(monkeypatch):
    from chimera.device.android import AndroidDeviceManager
    mgr = AndroidDeviceManager()

    async def ok(self_arg, device_id, argv):
        return "1\n"
    monkeypatch.setattr(AndroidDeviceManager, "_adb_device_argv", ok)
    alive = await mgr.is_alive("D")
    assert alive is True
