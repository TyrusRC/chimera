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
        await mgr._adb("devices")


async def test_pull_app_returns_all_split_apks(tmp_path, monkeypatch):
    from chimera.device.android import AndroidDeviceManager

    mgr = AndroidDeviceManager()

    async def fake_adb(device_id, args):
        if args.startswith("shell pm path"):
            return (
                "package:/data/app/base.apk\n"
                "package:/data/app/split_config.arm64_v8a.apk\n"
            )
        if args.startswith("pull "):
            _, src, dst = args.split()
            from pathlib import Path
            Path(dst).write_bytes(b"x")
        return ""

    monkeypatch.setattr(mgr, "_adb_device", fake_adb)

    paths = await mgr.pull_app("D", "com.x", str(tmp_path))
    assert isinstance(paths, list), f"expected list, got {type(paths)}"
    assert len(paths) == 2
    assert any("base.apk" in p for p in paths)
    assert any("split_config" in p for p in paths)
