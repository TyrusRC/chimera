from chimera.adapters.class_dump import ClassDumpAdapter
from chimera.adapters.base import ToolCategory


class TestClassDumpAdapter:
    def test_name(self):
        assert ClassDumpAdapter().name() == "class-dump"

    def test_supported_formats(self):
        formats = ClassDumpAdapter().supported_formats()
        assert "macho" in formats
        assert "fat" in formats

    def test_resource_is_light(self):
        req = ClassDumpAdapter().resource_estimate("/tmp/binary")
        assert req.category == ToolCategory.LIGHT

    async def test_cleanup(self):
        await ClassDumpAdapter().cleanup()
