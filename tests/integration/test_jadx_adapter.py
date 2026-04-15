import pytest
from chimera.adapters.jadx import JadxAdapter
from chimera.adapters.base import ToolCategory


class TestJadxAdapter:
    def test_name(self):
        assert JadxAdapter().name() == "jadx"

    def test_supported_formats(self):
        formats = JadxAdapter().supported_formats()
        assert "apk" in formats
        assert "dex" in formats
        assert "aab" in formats

    def test_resource_estimate_is_light(self):
        req = JadxAdapter().resource_estimate("/tmp/nonexistent.apk")
        assert req.category == ToolCategory.LIGHT

    async def test_cleanup(self):
        await JadxAdapter().cleanup()
