import pytest
from chimera.adapters.radare2 import Radare2Adapter


@pytest.fixture
def r2():
    adapter = Radare2Adapter()
    if not adapter.is_available():
        pytest.skip("radare2 not installed")
    return adapter


class TestRadare2Adapter:
    def test_name(self):
        assert Radare2Adapter().name() == "radare2"

    def test_supported_formats(self):
        formats = Radare2Adapter().supported_formats()
        assert "elf" in formats
        assert "macho" in formats
        assert "dex" in formats

    async def test_cleanup(self):
        await Radare2Adapter().cleanup()
