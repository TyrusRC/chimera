"""Main orchestrator — routes binaries to the correct pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.afl import AFLAdapter
from chimera.adapters.apktool import ApktoolAdapter
from chimera.adapters.class_dump import ClassDumpAdapter
from chimera.adapters.frida_adapter import FridaAdapter
from chimera.adapters.frida_dexdump import FridaDexdumpAdapter
from chimera.adapters.ghidra import GhidraAdapter
from chimera.adapters.jadx import JadxAdapter
from chimera.adapters.radare2 import Radare2Adapter
from chimera.adapters.registry import AdapterRegistry
from chimera.adapters.semgrep import SemgrepAdapter
from chimera.adapters.hermes_dec import HermesDecAdapter
from chimera.adapters.swift_demangle import SwiftDemangleAdapter
from chimera.adapters.webcrack import WebcrackAdapter
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import detect_platform

logger = logging.getLogger(__name__)


class ChimeraEngine:
    def __init__(self, config: ChimeraConfig):
        self.config = config
        self.cache = AnalysisCache(config.cache_dir)
        self.resource_mgr = ResourceManager(total_ram_mb=config.total_ram_mb)
        self.registry = AdapterRegistry()
        self._register_adapters()

    def _register_adapters(self) -> None:
        self.registry.register(Radare2Adapter())
        self.registry.register(GhidraAdapter(
            ghidra_home=self.config.ghidra_home,
            max_mem=self.config.ghidra_max_mem,
        ))
        self.registry.register(JadxAdapter())
        self.registry.register(ApktoolAdapter())
        self.registry.register(ClassDumpAdapter())
        self.registry.register(FridaAdapter())
        self.registry.register(FridaDexdumpAdapter())
        self.registry.register(AFLAdapter())
        self.registry.register(SemgrepAdapter())
        self.registry.register(WebcrackAdapter())
        self.registry.register(HermesDecAdapter())
        self.registry.register(SwiftDemangleAdapter())

    async def analyze(self, path: str | Path) -> UnifiedProgramModel:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")
        platform = detect_platform(path)
        logger.info("Detected platform: %s for %s", platform, path.name)
        if platform == "android":
            from chimera.pipelines.android import analyze_apk
            return await analyze_apk(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        elif platform == "ios":
            from chimera.pipelines.ios import analyze_ipa
            return await analyze_ipa(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        else:
            raise ValueError(f"Unsupported platform for {path.name}. Chimera only analyzes mobile binaries.")

    async def cleanup(self) -> None:
        for adapter in self.registry.all_registered():
            try:
                await adapter.cleanup()
            except Exception as exc:
                logger.warning("adapter %s cleanup failed: %s", adapter.name(), exc)
