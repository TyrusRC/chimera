"""Android APK analysis pipeline — orchestrates unpack, triage, decompile, map."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import _rehydrate_from_cache, unpack_apk

logger = logging.getLogger(__name__)


def _valid_r2_string(s: object) -> bool:
    return isinstance(s, dict) and isinstance(s.get("string"), str) and bool(s.get("string"))


def _valid_r2_function(f: object) -> bool:
    if not isinstance(f, dict):
        return False
    off = f.get("offset", f.get("vaddr"))
    return isinstance(off, (int, str))


async def analyze_apk(
    apk_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    apk_path = Path(apk_path)
    binary = BinaryInfo.from_path(apk_path)

    if cache.has(binary.sha256):
        cached_triage = cache.get_json(binary.sha256, "triage")
        if cached_triage:
            if cached_triage.get("status") == "skipped":
                logger.warning(
                    "Cached analysis for %s was skipped: %s",
                    binary.sha256[:12], cached_triage.get("reason", "unknown"),
                )
                model = UnifiedProgramModel(binary)
                from chimera.model.binary import Framework
                try:
                    binary.framework = Framework(cached_triage.get("framework", "native"))
                except ValueError:
                    binary.framework = Framework.NATIVE
                return model
            logger.info("Cache hit for %s - reusing triage", binary.sha256[:12])
            model = UnifiedProgramModel(binary)
            from chimera.model.binary import Framework
            try:
                binary.framework = Framework(cached_triage.get("framework", "native"))
            except ValueError:
                binary.framework = Framework.NATIVE
            _rehydrate_from_cache(model, cache, binary.sha256, language="c", layer="native")
            return model

    model = UnifiedProgramModel(binary)
    skipped_phases: list[str] = []

    # Phase 1: Unpack
    logger.info("Unpacking APK")
    unpack_dir = config.project_dir / "unpacked" / binary.sha256[:12]
    unpack_result = unpack_apk(apk_path, unpack_dir)

    # Phase 2: Framework detection
    from chimera.frameworks.detector import FrameworkDetector
    from chimera.model.binary import Framework
    detect_dir = unpack_result["output_dir"]
    detected = FrameworkDetector.detect(detect_dir)
    try:
        binary.framework = Framework(detected.framework)
    except ValueError:
        binary.framework = Framework.NATIVE
    logger.info("Framework detected: %s%s",
                detected.framework,
                f" ({detected.variant})" if detected.variant else "")

    # Phase 3: Read manifest (useful for RE even without vuln scan)
    manifest_xml = None
    jadx_sources = None
    jadx = registry.get("jadx")

    # Try jadx-decoded manifest first (after jadx runs), fallback to raw
    if unpack_result["manifest_path"].exists():
        try:
            raw = unpack_result["manifest_path"].read_text(errors="replace")
            if raw.lstrip().startswith("<?xml") or raw.lstrip().startswith("<manifest"):
                manifest_xml = raw
        except OSError:
            pass

    # Phase 4: r2 triage on native libraries
    r2 = registry.get("radare2")
    if not (r2 and r2.is_available() and unpack_result["has_native"]):
        if unpack_result["has_native"]:
            skipped_phases.append("radare2")
            logger.warning("radare2 unavailable — skipping native triage")
    else:
        logger.info("r2 triage on %d native libraries", len(unpack_result["native_libs"]))

        async def _r2_triage(lib_path: Path) -> None:
            async with resource_mgr.light():
                triage = await r2.analyze(str(lib_path), {"mode": "triage"})
                for s in triage.get("strings", []):
                    if not _valid_r2_string(s):
                        continue
                    model.add_string(
                        address=str(s.get("vaddr", "0x0")),
                        value=s["string"],
                        section=s.get("section", None),
                    )
                for f in triage.get("functions", []):
                    if not _valid_r2_function(f):
                        continue
                    offset = f.get("offset", f.get("vaddr", 0))
                    addr = hex(offset) if isinstance(offset, int) else str(offset)
                    fname = f.get("name") or f.get("realname") or f"FUN_{addr}"
                    model.add_function(FunctionInfo(
                        address=addr,
                        name=fname,
                        original_name=fname,
                        language="c", classification="unknown",
                        layer="native", source_backend="radare2",
                    ))
                cache.put_json(binary.sha256, f"r2_{lib_path.name}", triage)

        await asyncio.gather(*[_r2_triage(lib) for lib in unpack_result["native_libs"]])

    # Phase 5: Decompile with jadx
    if not (jadx and jadx.is_available()):
        skipped_phases.append("jadx")
        logger.warning("jadx unavailable — skipping decompile")
    else:
        logger.info("jadx decompilation")
        jadx_output = config.project_dir / "jadx" / binary.sha256[:12]
        jadx_input = unpack_result.get("base_apk_path", apk_path)
        async with resource_mgr.light():
            jadx_result = await jadx.analyze(str(jadx_input), {"output_dir": str(jadx_output)})
            cache.put_json(binary.sha256, "jadx", {
                "decompiled_files": jadx_result.get("decompiled_files", 0),
                "packages": jadx_result.get("packages", []),
            })
            logger.info("jadx: %d files decompiled", jadx_result.get("decompiled_files", 0))

        # Update manifest from jadx-decoded version (more reliable than raw)
        jadx_sources = jadx_output / "sources"
        jadx_manifest = jadx_output / "resources" / "AndroidManifest.xml"
        if jadx_manifest.exists():
            try:
                manifest_xml = jadx_manifest.read_text(errors="replace")
            except OSError:
                pass

    if manifest_xml is None:
        logger.warning("AndroidManifest.xml is binary-encoded. Install jadx for proper manifest analysis.")

    # Store decoded manifest in cache for MCP access
    if manifest_xml:
        cache.put(binary.sha256, "manifest_xml", manifest_xml.encode())

    # Phase 6: Ghidra deep analysis on native libraries
    ghidra = registry.get("ghidra")
    if not (ghidra and ghidra.is_available() and unpack_result["has_native"]):
        if unpack_result["has_native"]:
            skipped_phases.append("ghidra")
            logger.warning("ghidra unavailable — skipping deep analysis")
    else:
        logger.info("Ghidra deep analysis on native libraries")

        async def _ghidra_analyze(lib_path: Path) -> None:
            async with resource_mgr.heavy():
                ghidra_result = await ghidra.analyze(str(lib_path), {
                    "mode": "decompile",
                    "project_dir": str(config.project_dir / "ghidra"),
                })
                cache.put_json(binary.sha256, f"ghidra_{lib_path.name}", ghidra_result)

        await asyncio.gather(*[_ghidra_analyze(lib) for lib in unpack_result["native_libs"]])

    cache.put_json(binary.sha256, "triage", {
        "platform": "android",
        "format": binary.format.value,
        "framework": binary.framework.value,
        "dex_count": unpack_result["dex_count"],
        "has_native": unpack_result["has_native"],
        "native_lib_count": len(unpack_result["native_libs"]),
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "bundle_format": unpack_result.get("bundle_format"),
        "skipped_phases": skipped_phases,
    })

    logger.info("Analysis complete: %d functions, %d strings",
                len(model.functions), len(model.get_strings()))
    return model
