"""Linux memory-image analysis pipeline.

Stub: detection + minimal model construction. Phases 3 (analysis pipeline),
4 (persistence enumeration), and 5 (IR findings) fill in the actual work.
This stub exists so the engine can route memory-image inputs without
crashing.
"""
from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo, Platform
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


async def analyze_memory(
    image_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Triage a Linux memory image. Phases will be filled in subsequent tasks."""
    image_path = Path(image_path)
    binary = BinaryInfo.from_path(image_path)
    # Force the platform tuple — `_guess_platform` already maps memory
    # formats to LINUX_MEMORY but be defensive in case the route taken
    # by `_detect_format` was suffix-based and missed it.
    binary.platform = Platform.LINUX_MEMORY
    model = UnifiedProgramModel(binary)
    logger.info("Memory pipeline (stub): %s [%s]",
                image_path.name, binary.format.value)
    return model
