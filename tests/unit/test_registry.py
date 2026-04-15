import pytest
from chimera.adapters.registry import AdapterRegistry
from chimera.adapters.base import BackendAdapter, ToolCategory, ResourceRequirement


class MockAdapter(BackendAdapter):
    def __init__(self, adapter_name: str, formats: list[str], available: bool = True):
        self._name = adapter_name
        self._formats = formats
        self._available = available
    def name(self) -> str: return self._name
    def is_available(self) -> bool: return self._available
    def supported_formats(self) -> list[str]: return self._formats
    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=256, category=ToolCategory.LIGHT, estimated_seconds=5)
    async def analyze(self, binary_path: str, options: dict) -> dict: return {}
    async def cleanup(self) -> None: pass


class TestAdapterRegistry:
    def test_register_and_get(self):
        registry = AdapterRegistry()
        adapter = MockAdapter("r2", ["elf", "macho"])
        registry.register(adapter)
        assert registry.get("r2") is adapter

    def test_get_missing_returns_none(self):
        registry = AdapterRegistry()
        assert registry.get("nonexistent") is None

    def test_find_for_format(self):
        registry = AdapterRegistry()
        registry.register(MockAdapter("jadx", ["apk", "dex"]))
        registry.register(MockAdapter("ghidra", ["elf", "macho", "dex"]))
        adapters = registry.find_for_format("dex")
        names = [a.name() for a in adapters]
        assert "jadx" in names
        assert "ghidra" in names

    def test_find_for_format_excludes_unavailable(self):
        registry = AdapterRegistry()
        registry.register(MockAdapter("available", ["elf"], available=True))
        registry.register(MockAdapter("broken", ["elf"], available=False))
        adapters = registry.find_for_format("elf")
        assert len(adapters) == 1
        assert adapters[0].name() == "available"

    def test_all_available(self):
        registry = AdapterRegistry()
        registry.register(MockAdapter("a", ["elf"], available=True))
        registry.register(MockAdapter("b", ["elf"], available=False))
        registry.register(MockAdapter("c", ["dex"], available=True))
        available = registry.all_available()
        names = [a.name() for a in available]
        assert "a" in names
        assert "c" in names
        assert "b" not in names
