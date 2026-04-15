import pytest
from chimera.adapters.base import BackendAdapter, ToolCategory, ResourceRequirement


class FakeAdapter(BackendAdapter):
    def name(self) -> str: return "fake"
    def is_available(self) -> bool: return True
    def supported_formats(self) -> list[str]: return ["apk", "elf"]
    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=512, category=ToolCategory.LIGHT, estimated_seconds=10)
    async def analyze(self, binary_path: str, options: dict) -> dict: return {"status": "ok"}
    async def cleanup(self) -> None: pass


class TestBackendAdapter:
    def test_fake_adapter_implements_interface(self):
        adapter = FakeAdapter()
        assert adapter.name() == "fake"
        assert adapter.is_available() is True
        assert "apk" in adapter.supported_formats()

    def test_resource_requirement(self):
        adapter = FakeAdapter()
        req = adapter.resource_estimate("/tmp/test.apk")
        assert req.memory_mb == 512
        assert req.category == ToolCategory.LIGHT

    async def test_analyze(self):
        adapter = FakeAdapter()
        result = await adapter.analyze("/tmp/test.apk", {})
        assert result["status"] == "ok"

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BackendAdapter()
