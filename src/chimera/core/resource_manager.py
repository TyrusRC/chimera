"""Resource manager — ensures heavy tools don't compete for RAM."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator


class ResourceManager:
    MIN_RAM_MB = 4096  # Minimum 4GB for basic static analysis

    def __init__(self, total_ram_mb: int | None = None):
        import logging
        logger = logging.getLogger(__name__)
        if total_ram_mb is None:
            total_ram_mb = _detect_ram_mb()
        if total_ram_mb < self.MIN_RAM_MB:
            raise SystemError(
                f"Chimera requires minimum 4GB RAM. Detected: {total_ram_mb}MB"
            )
        if total_ram_mb < 16384:
            logger.warning(
                "Less than 16GB RAM detected (%dMB). "
                "Heavy tools (Ghidra) may be slow or fail. 16GB+ recommended.",
                total_ram_mb,
            )
        self.total_ram_mb = total_ram_mb
        self.high_memory = total_ram_mb >= 32768
        heavy_concurrent = 2 if self.high_memory else 1
        light_concurrent = 6 if self.high_memory else 4
        self._heavy_sem = asyncio.Semaphore(heavy_concurrent)
        self._light_sem = asyncio.Semaphore(light_concurrent)

    @property
    def heavy_max_mem(self) -> str:
        return "6g" if self.high_memory else "4g"

    @asynccontextmanager
    async def heavy(self) -> AsyncIterator[None]:
        async with self._heavy_sem:
            yield

    @asynccontextmanager
    async def light(self) -> AsyncIterator[None]:
        async with self._light_sem:
            yield


def _detect_ram_mb() -> int:
    try:
        import psutil
        return psutil.virtual_memory().total // (1024 * 1024)
    except ImportError:
        pass
    try:
        import os
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            return (pages * page_size) // (1024 * 1024)
    except (ValueError, OSError):
        pass
    return 16384
