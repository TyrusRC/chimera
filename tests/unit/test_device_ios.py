from chimera.device.ios import IOSDeviceManager


class TestIOSDeviceManager:
    def test_name(self):
        assert IOSDeviceManager().name == "ios"

    def test_is_available_checks_tools(self):
        _ = IOSDeviceManager().is_available

    async def test_cleanup(self):
        await IOSDeviceManager().cleanup()
