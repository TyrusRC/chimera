from chimera.adapters.afl import AFLAdapter
from chimera.adapters.base import ToolCategory


class TestAFLAdapter:
    def test_name(self):
        assert AFLAdapter().name() == "afl++"

    def test_supported_formats(self):
        formats = AFLAdapter().supported_formats()
        assert "elf" in formats

    def test_resource_is_heavy(self):
        req = AFLAdapter().resource_estimate("/tmp/test.so")
        assert req.category == ToolCategory.HEAVY

    def test_build_qemu_command(self):
        adapter = AFLAdapter()
        cmd = adapter._build_fuzz_command(
            binary="/tmp/harness",
            input_dir="/tmp/input",
            output_dir="/tmp/output",
            qemu_mode=True,
            timeout_ms=1000,
        )
        assert "afl-fuzz" in cmd[0] or "afl-fuzz" in " ".join(cmd)
        assert "-Q" in cmd  # QEMU mode
        assert "-i" in cmd
        assert "-o" in cmd

    async def test_cleanup(self):
        await AFLAdapter().cleanup()
