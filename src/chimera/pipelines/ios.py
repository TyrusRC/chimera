"""iOS IPA analysis pipeline — orchestrates unpack, metadata, binary analysis."""

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
from chimera.pipelines.android import _valid_r2_string, _valid_r2_function
from chimera.pipelines.common import _rehydrate_from_cache, unpack_ipa

logger = logging.getLogger(__name__)


async def analyze_ipa(
    ipa_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Run the full iOS static analysis pipeline on an IPA."""

    ipa_path = Path(ipa_path)
    binary = BinaryInfo.from_path(ipa_path)

    if cache.has(binary.sha256):
        cached = cache.get_json(binary.sha256, "triage")
        if cached:
            logger.info("Cache hit for %s - reusing triage", binary.sha256[:12])
            model = UnifiedProgramModel(binary)
            from chimera.model.binary import Framework
            try:
                binary.framework = Framework(cached.get("framework", "native"))
            except ValueError:
                binary.framework = Framework.NATIVE
            _rehydrate_from_cache(model, cache, binary.sha256, language="objc", layer="native")
            return model

    model = UnifiedProgramModel(binary)

    # Phase 1: Unpack IPA
    logger.info("Unpacking IPA")
    unpack_dir = config.project_dir / "unpacked" / binary.sha256[:12]
    unpack_result = unpack_ipa(ipa_path, unpack_dir)

    # Phase 2: Framework detection
    from chimera.frameworks.detector import FrameworkDetector
    from chimera.model.binary import Framework
    detected = FrameworkDetector.detect(
        unpack_result["app_bundle"] if unpack_result["app_bundle"] else unpack_dir
    )
    try:
        binary.framework = Framework(detected.framework)
    except ValueError:
        binary.framework = Framework.NATIVE
    logger.info("Framework detected: %s%s",
                detected.framework,
                f" ({detected.variant})" if detected.variant else "")

    if not unpack_result["app_bundle"]:
        logger.error("No .app bundle found in IPA")
        cache.put_json(binary.sha256, "triage", {
            "platform": "ios",
            "status": "skipped",
            "reason": "no_app_bundle",
            "framework": binary.framework.value,
        })
        return model

    plist = unpack_result["plist"]
    logger.info("Bundle: %s (%s)", plist.get("CFBundleName", "?"), unpack_result["bundle_id"])

    # Cache plist for MCP access
    import json
    cache.put(binary.sha256, "info_plist", json.dumps(
        {k: str(v) for k, v in plist.items()}, indent=2
    ).encode())

    # Phase 3: r2 triage on main binary + frameworks
    all_binaries: list[Path] = []
    if unpack_result["main_binary"]:
        all_binaries.append(unpack_result["main_binary"])
    all_binaries.extend(p for p in unpack_result["frameworks"] if p is not None)
    all_binaries.extend(p for p in unpack_result["extensions"] if p is not None)

    r2 = registry.get("radare2")
    if r2 and r2.is_available() and all_binaries:
        logger.info("r2 triage on %d binaries", len(all_binaries))

        async def _r2_triage(bin_path: Path) -> None:
            async with resource_mgr.light():
                triage = await r2.analyze(str(bin_path), {"mode": "triage"})
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
                        language="objc",
                        classification="unknown",
                        layer="native",
                        source_backend="radare2",
                    ))
                cache.put_json(binary.sha256, f"r2_{bin_path.name}", triage)

        await asyncio.gather(*[_r2_triage(bp) for bp in all_binaries])

    # Phase 4: ObjC header extraction
    class_dump = registry.get("class-dump")
    if class_dump and class_dump.is_available() and unpack_result["main_binary"]:
        logger.info("ObjC header extraction")
        async with resource_mgr.light():
            headers_dir = config.project_dir / "headers" / binary.sha256[:12]
            cd_result = await class_dump.analyze(
                str(unpack_result["main_binary"]),
                {"output_dir": str(headers_dir)},
            )
            cache.put_json(binary.sha256, "class_dump", {
                "header_count": cd_result.get("header_count", 0),
                "classes": cd_result.get("classes", []),
            })
            logger.info("class-dump: %d headers extracted",
                        cd_result.get("header_count", 0))

    # Phase 5: Ghidra deep analysis on main binary
    ghidra = registry.get("ghidra")
    if ghidra and ghidra.is_available() and unpack_result["main_binary"]:
        logger.info("Ghidra deep analysis")
        async with resource_mgr.heavy():
            ghidra_result = await ghidra.analyze(
                str(unpack_result["main_binary"]),
                {"mode": "decompile", "project_dir": str(config.project_dir / "ghidra")},
            )
            cache.put_json(binary.sha256, "ghidra_main", ghidra_result)

    cache.put_json(binary.sha256, "triage", {
        "platform": "ios",
        "framework": binary.framework.value,
        "bundle_id": unpack_result["bundle_id"],
        "binary_count": len(all_binaries),
        "framework_count": len(unpack_result["frameworks"]),
        "extension_count": len(unpack_result["extensions"]),
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
    })

    logger.info("Analysis complete: %d functions, %d strings",
                len(model.functions), len(model.get_strings()))
    return model
