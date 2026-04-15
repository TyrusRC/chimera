from chimera.adapters.frida_adapter import FridaAdapter
from chimera.adapters.base import ToolCategory


class TestFridaAdapter:
    def test_name(self):
        assert FridaAdapter().name() == "frida"

    def test_supported_formats(self):
        formats = FridaAdapter().supported_formats()
        assert "apk" in formats
        assert "ipa" in formats

    def test_resource_is_light(self):
        req = FridaAdapter().resource_estimate("")
        assert req.category == ToolCategory.LIGHT

    async def test_cleanup(self):
        await FridaAdapter().cleanup()
