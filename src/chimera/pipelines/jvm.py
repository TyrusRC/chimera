"""Plain JVM archive (.jar) analysis pipeline.

A desktop Java program is a ZIP of `.class` files with no
AndroidManifest.xml, so it fell through every Android/iOS branch and
`chimera analyze` rejected it outright — even though jadx, which chimera
already ships an adapter for, decompiles a `.jar` natively.

This pipeline is deliberately thin: jadx does the work, and the existing
`jvm_ingest` helpers (shared with the Android pipeline) populate the
model. There is no native layer to triage — no r2, no Ghidra — so unlike
the ELF/PE pipelines this one has a single backend.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry
from chimera.model.binary import BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


async def analyze_jar(
    jar_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Decompile a .jar with jadx and ingest its classes/methods."""
    jar_path = Path(jar_path)

    binary = BinaryInfo.from_path(jar_path)
    binary.format = BinaryFormat.JAR
    binary.platform = Platform.JVM
    binary.framework = Framework.NONE
    sha = binary.sha256

    model = UnifiedProgramModel(binary)
    skipped_phases: list[str] = []

    if cache.has(sha):
        cached = cache.get_json(sha, "triage") or {}
        cached_sources = cached.get("sources_dir")
        # Only a run that actually produced sources is worth replaying. A
        # run with jadx missing (or a since-deleted output tree) cached an
        # empty result, and treating that as a hit made the emptiness
        # permanent: install jadx, re-run, still get zero functions. Fall
        # through and re-analyze instead.
        if cached_sources and Path(cached_sources).exists():
            logger.info("Cache hit for %s — reusing triage", sha[:12])
            _ingest(model, Path(cached_sources), config)
            return model
        if cached:
            logger.info(
                "Cached analysis for %s recovered nothing — re-analyzing",
                sha[:12],
            )

    logger.info("JVM pipeline: %s [%s]", jar_path.name, binary.format.value)

    jadx = registry.get("jadx")
    sources_dir: Path | None = None
    if not (jadx and jadx.is_available()):
        skipped_phases.append("jadx")
        logger.warning(
            "jadx unavailable — cannot decompile %s. A .jar has no native "
            "layer to fall back on, so no code will be recovered.",
            jar_path.name,
        )
    else:
        jadx_output = config.project_dir / "jadx" / sha[:12]
        try:
            async with resource_mgr.light():
                result = await jadx.analyze(str(jar_path), {
                    "output_dir": str(jadx_output),
                    "deobf_cache_dir": str(config.cache_dir / "jadx_deobf" / sha[:12]),
                })
            cache.put_json(sha, "jadx", {
                "decompiled_files": result.get("decompiled_files", 0),
                "packages": result.get("packages", []),
                "sources_dir": result.get("sources_dir"),
            })
            candidate = Path(result.get("sources_dir", ""))
            if candidate.exists():
                sources_dir = candidate
            logger.info("jadx: %d decompiled files, %d packages",
                        result.get("decompiled_files", 0),
                        len(result.get("packages", [])))
        except Exception as exc:
            logger.warning("jadx phase failed: %s", exc)
            skipped_phases.append("jadx")

    if sources_dir is not None:
        _ingest(model, sources_dir, config)

    cache.put_json(sha, "triage", {
        "format": binary.format.value,
        "platform": binary.platform.value,
        "framework": binary.framework.value,
        "sources_dir": str(sources_dir) if sources_dir else None,
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "skipped_phases": skipped_phases,
    })
    logger.info("JVM analysis complete: %d functions, %d strings",
                len(model.functions), len(model.get_strings()))
    return model


def _ingest(model: UnifiedProgramModel, sources_dir: Path,
            config: ChimeraConfig) -> None:
    """Replay the jadx source tree into the model (shared with Android)."""
    from chimera.pipelines.jvm_ingest import (
        ingest_jadx_classes,
        ingest_jadx_methods,
    )

    classes_added, strings_added = ingest_jadx_classes(model, sources_dir)
    logger.info("ingested %d classes / %d strings from jadx",
                classes_added, strings_added)
    if not getattr(config, "skip_jvm_methods", False):
        methods_added = ingest_jadx_methods(model, sources_dir)
        logger.info("ingested %d methods from jadx", methods_added)
