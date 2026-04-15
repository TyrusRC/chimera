from chimera.adapters.semgrep import SemgrepAdapter
from chimera.adapters.base import ToolCategory


class TestSemgrepAdapter:
    def test_name(self):
        assert SemgrepAdapter().name() == "semgrep"

    def test_supported_formats(self):
        assert "java" in SemgrepAdapter().supported_formats()
        assert "kotlin" in SemgrepAdapter().supported_formats()

    def test_resource_is_light(self):
        req = SemgrepAdapter().resource_estimate("/tmp/sources")
        assert req.category == ToolCategory.LIGHT
