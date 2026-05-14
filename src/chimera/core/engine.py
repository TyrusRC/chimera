"""Main orchestrator — routes binaries to the correct pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.afl import AFLAdapter
from chimera.adapters.apktool import ApktoolAdapter
from chimera.adapters.capa_adapter import CapaAdapter
from chimera.adapters.class_dump import ClassDumpAdapter
from chimera.adapters.floss import FlossAdapter
from chimera.adapters.frida_adapter import FridaAdapter
from chimera.adapters.frida_dexdump import FridaDexdumpAdapter
from chimera.adapters.ghidra import GhidraAdapter
from chimera.adapters.ilspy import IlspyAdapter
from chimera.adapters.jadx import JadxAdapter
from chimera.adapters.radare2 import Radare2Adapter
from chimera.adapters.registry import AdapterRegistry
from chimera.adapters.semgrep import SemgrepAdapter
from chimera.adapters.hermes_dec import HermesDecAdapter
from chimera.adapters.swift_demangle import SwiftDemangleAdapter
from chimera.adapters.volatility import VolatilityAdapter
from chimera.adapters.webcrack import WebcrackAdapter
from chimera.adapters.yara_adapter import YaraAdapter
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import detect_platform

logger = logging.getLogger(__name__)


class UnsupportedFormatError(Exception):
    """Raised by ChimeraEngine.analyze when the input format has no pipeline."""

    SUPPORTED = (
        "APK/AAB/XAPK/APKM/DEX  -> android",
        "IPA                    -> ios",
        "MACHO/DYLIB/FAT        -> macho (standalone)",
        "PE32/PE64/DOTNET       -> windows",
        "ELF                    -> linux native",
        "MEMORY_LIME/RAW        -> memory forensics",
    )

    def __init__(self, detected_format: str | None, path: str):
        self.detected_format = detected_format
        self.path = path
        supported = "\n  ".join(self.SUPPORTED)
        super().__init__(
            f"Unsupported format {detected_format!r} for {path!r}. "
            f"Supported formats:\n  {supported}"
        )


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
        self.registry.register(YaraAdapter())
        self.registry.register(CapaAdapter())
        self.registry.register(FlossAdapter())
        self.registry.register(IlspyAdapter())
        self.registry.register(VolatilityAdapter())

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
            # Bare Mach-O / FAT / DYLIB inputs must NOT go through analyze_ipa
            # — that pipeline expects a zip archive and crashes on raw
            # binaries. Branch on BinaryInfo.format to pick the right route.
            from chimera.model.binary import BinaryFormat, BinaryInfo
            fmt = BinaryInfo.from_path(path).format
            if fmt == BinaryFormat.IPA:
                from chimera.pipelines.ios import analyze_ipa
                return await analyze_ipa(
                    path, self.config, self.registry, self.resource_mgr, self.cache,
                )
            from chimera.pipelines.macho import analyze_macho
            return await analyze_macho(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        elif platform == "windows":
            from chimera.pipelines.pe import analyze_pe
            return await analyze_pe(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        elif platform == "linux_native":
            from chimera.pipelines.elf import analyze_elf
            return await analyze_elf(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        elif platform == "linux_memory":
            from chimera.pipelines.memory import analyze_memory
            return await analyze_memory(
                path, self.config, self.registry, self.resource_mgr, self.cache,
            )
        else:
            detected: str | None = None
            try:
                from chimera.model.binary import BinaryInfo
                detected = BinaryInfo.from_path(path).format.value
            except Exception:
                pass
            raise UnsupportedFormatError(detected, str(path))

    async def cleanup(self) -> None:
        for adapter in self.registry.all_registered():
            try:
                await adapter.cleanup()
            except Exception as exc:
                logger.warning("adapter %s cleanup failed: %s", adapter.name(), exc)
