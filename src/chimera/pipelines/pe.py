"""Windows PE analysis pipeline.

Stub: detection + minimal model construction. Phases 4 fills in r2/Ghidra/
FLOSS/ILSpy/import-scoring/native-protection. This stub exists so the
engine can route PE inputs without crashing.
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


async def analyze_pe(
    pe_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Triage a Windows PE binary. Phases will be filled in subsequent tasks."""
    pe_path = Path(pe_path)
    binary = BinaryInfo.from_path(pe_path)
    model = UnifiedProgramModel(binary)
    logger.info("PE pipeline (stub): %s [%s]", pe_path.name, binary.format.value)
    return model
