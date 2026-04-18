import asyncio
import pytest
from chimera.core.resource_manager import ResourceManager


class TestResourceManager:
    def test_create_with_defaults(self):
        rm = ResourceManager(total_ram_mb=16384)
        assert rm.total_ram_mb == 16384
        assert rm.high_memory is False

    def test_high_memory_mode(self):
        rm = ResourceManager(total_ram_mb=32768)
        assert rm.high_memory is True

    def test_rejects_low_ram(self):
        with pytest.raises(SystemError, match="4GB RAM"):
            ResourceManager(total_ram_mb=2048)

    async def test_heavy_tasks_serialize(self):
        rm = ResourceManager(total_ram_mb=16384)
        execution_order = []
        async def heavy_task(name, delay=0.05):
            async with rm.heavy():
                execution_order.append(f"{name}_start")
                await asyncio.sleep(delay)
                execution_order.append(f"{name}_end")
        await asyncio.gather(heavy_task("ghidra"), heavy_task("joern"))
        assert execution_order[0] == "ghidra_start"
        assert execution_order[1] == "ghidra_end"
        assert execution_order[2] == "joern_start"
        assert execution_order[3] == "joern_end"

    async def test_light_tasks_parallel(self):
        rm = ResourceManager(total_ram_mb=16384)
        execution_order = []
        async def light_task(name):
            async with rm.light():
                execution_order.append(f"{name}_start")
                await asyncio.sleep(0.05)
                execution_order.append(f"{name}_end")
        await asyncio.gather(light_task("r2"), light_task("jadx"))
        starts = [e for e in execution_order if "start" in e]
        assert len(starts) == 2
        assert execution_order.index("r2_start") < execution_order.index("r2_end")
        assert execution_order.index("jadx_start") < execution_order.index("jadx_end")

    def test_max_memory_for_heavy(self):
        rm_16 = ResourceManager(total_ram_mb=16384)
        rm_32 = ResourceManager(total_ram_mb=32768)
        assert rm_16.heavy_max_mem == "4g"
        assert rm_32.heavy_max_mem == "6g"
