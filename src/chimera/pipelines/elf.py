"""Standalone Linux ELF analysis pipeline.

Stub: detection + minimal model construction. Phase 4 fills in
r2/Ghidra/FLOSS/persistence-scanner/syscall-scoring/native-protection.
"""
from __future__ import annotations

import logging
from pathlib import Path

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.adapters.registry import AdapterRegistry
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


async def analyze_elf(
    elf_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Triage a standalone Linux ELF binary."""
    elf_path = Path(elf_path)
    binary = BinaryInfo.from_path(elf_path)
    model = UnifiedProgramModel(binary)
    logger.info("ELF pipeline (stub): %s [%s]", elf_path.name, binary.format.value)
    return model
