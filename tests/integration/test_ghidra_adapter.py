import pytest
from chimera.adapters.ghidra import GhidraAdapter
from chimera.adapters.base import ToolCategory


class TestGhidraAdapter:
    def test_name(self):
        assert GhidraAdapter().name() == "ghidra"

    def test_supported_formats(self):
        formats = GhidraAdapter().supported_formats()
        assert "elf" in formats
        assert "macho" in formats
        assert "dex" in formats

    def test_resource_estimate_is_heavy(self):
        adapter = GhidraAdapter()
        req = adapter.resource_estimate("/tmp/nonexistent.so")
        assert req.category == ToolCategory.HEAVY
        assert req.memory_mb >= 2048

    async def test_cleanup(self):
        await GhidraAdapter().cleanup()
