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
from chimera.pipelines.common import unpack_apk

logger = logging.getLogger(__name__)


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
            logger.info("Cache hit for %s — skipping to vuln detection", binary.sha256[:12])

    model = UnifiedProgramModel(binary)

    # Phase 2: Unpack
    logger.info("Phase 2: Unpacking APK")
    unpack_dir = config.project_dir / "unpacked" / binary.sha256[:12]
    unpack_result = unpack_apk(apk_path, unpack_dir)

    # Phase 2.5: Framework detection
    from chimera.frameworks.detector import FrameworkDetector
    from chimera.model.binary import Framework
    detected = FrameworkDetector.detect(unpack_dir)
    try:
        binary.framework = Framework(detected.framework)
    except ValueError:
        binary.framework = Framework.NATIVE
    logger.info("Framework detected: %s%s",
                detected.framework,
                f" ({detected.variant})" if detected.variant else "")

    # Phase 3: Triage with r2
    r2 = registry.get("radare2")
    if r2 and r2.is_available() and unpack_result["has_native"]:
        logger.info("Phase 3: r2 triage on %d native libraries", len(unpack_result["native_libs"]))

        async def _r2_triage(lib_path: Path) -> None:
            async with resource_mgr.light():
                triage = await r2.analyze(str(lib_path), {"mode": "full"})
                for s in triage.get("strings", []):
                    if isinstance(s, dict) and "string" in s:
                        model.add_string(
                            address=str(s.get("vaddr", "0x0")),
                            value=s["string"],
                            section=s.get("section", None),
                        )
                for f in triage.get("functions", []):
                    if isinstance(f, dict) and "offset" in f:
                        offset = f["offset"]
                        addr = hex(offset) if isinstance(offset, int) else str(offset)
                        fname = f.get("name") or f"FUN_{addr}"
                        model.add_function(FunctionInfo(
                            address=addr,
                            name=fname,
                            original_name=fname,
                            language="c", classification="unknown",
                            layer="native", source_backend="radare2",
                        ))
                cache.put_json(binary.sha256, f"r2_{lib_path.name}", triage)

        await asyncio.gather(*[_r2_triage(lib) for lib in unpack_result["native_libs"]])

    # Phase 4: Decompile with jadx
    jadx = registry.get("jadx")
    if jadx and jadx.is_available():
        logger.info("Phase 4: jadx decompilation")
        jadx_output = config.project_dir / "jadx" / binary.sha256[:12]
        async with resource_mgr.light():
            jadx_result = await jadx.analyze(str(apk_path), {"output_dir": str(jadx_output)})
            cache.put_json(binary.sha256, "jadx", {
                "decompiled_files": jadx_result.get("decompiled_files", 0),
                "packages": jadx_result.get("packages", []),
            })
            logger.info("jadx: %d files decompiled", jadx_result.get("decompiled_files", 0))

    # Phase 5: Deep analysis with Ghidra
    ghidra = registry.get("ghidra")
    if ghidra and ghidra.is_available() and unpack_result["has_native"]:
        logger.info("Phase 5: Ghidra deep analysis on native libraries")

        async def _ghidra_analyze(lib_path: Path) -> None:
            async with resource_mgr.heavy():
                ghidra_result = await ghidra.analyze(str(lib_path), {
                    "mode": "decompile",
                    "project_dir": str(config.project_dir / "ghidra"),
                })
                cache.put_json(binary.sha256, f"ghidra_{lib_path.name}", ghidra_result)

        await asyncio.gather(*[_ghidra_analyze(lib) for lib in unpack_result["native_libs"]])

    # Phase 6: Vulnerability detection
    from chimera.vuln.engine import VulnEngine

    logger.info("Phase 6: Vulnerability detection")
    vuln_engine = VulnEngine()

    manifest_xml = None
    if unpack_result["manifest_path"].exists():
        try:
            manifest_xml = unpack_result["manifest_path"].read_text(errors="replace")
        except OSError:
            pass

    jadx_sources = None
    if jadx and jadx.is_available():
        jadx_sources = config.project_dir / "jadx" / binary.sha256[:12] / "sources"

    findings = await vuln_engine.scan(
        platform="android",
        manifest_xml=manifest_xml,
        jadx_sources_dir=jadx_sources,
        native_libs=unpack_result["native_libs"],
        strings=[{"string": s.value, "address": s.address} for s in model.get_strings()],
        unpack_dir=unpack_dir,
    )

    model.findings = findings
    logger.info("Found %d vulnerabilities", len(findings))

    cache.put_json(binary.sha256, "triage", {
        "platform": "android",
        "dex_count": unpack_result["dex_count"],
        "has_native": unpack_result["has_native"],
        "native_lib_count": len(unpack_result["native_libs"]),
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "finding_count": len(findings),
    })

    logger.info("Analysis complete: %d functions, %d strings, %d findings",
                len(model.functions), len(model.get_strings()), len(findings))
    return model
