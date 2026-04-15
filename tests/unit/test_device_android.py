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
