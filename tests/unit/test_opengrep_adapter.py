from chimera.adapters.opengrep import OpengrepAdapter
from chimera.adapters.base import ToolCategory


class TestOpengrepAdapter:
    def test_name(self):
        assert OpengrepAdapter().name() == "opengrep"

    def test_supported_formats(self):
        assert "java" in OpengrepAdapter().supported_formats()
        assert "kotlin" in OpengrepAdapter().supported_formats()

    def test_resource_is_light(self):
        req = OpengrepAdapter().resource_estimate("/tmp/sources")
        assert req.category == ToolCategory.LIGHT
