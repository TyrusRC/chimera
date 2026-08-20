"""Standalone Mach-O / FAT / dylib analysis pipeline.

Mirrors the PE/ELF standalone pipelines for bare iOS / macOS binaries
that arrive without an enclosing IPA archive. The IPA pipeline owns the
unpack + per-binary fanout flow; this one is for analysts who drop a
single Mach-O, FAT slice, or .dylib on the engine.

Phases
------
1. Triage cache check — rehydrate and return if hit.
2. BinaryInfo + model setup.
3. r2 triage — functions + strings from the native layer (skipped if
   radare2 is unavailable).
4. ObjC metadata parse — best-effort __objc_classlist / __objc_methlist
   extraction via chimera.parsers.macho_objc.
5. YARA — crypto constants + commercial packer detection.
6. Capa — capability tags.
7. Final triage cache write.

Notes
-----
- FAT/Universal binaries are dispatched through this pipeline whole; the
  ObjC parser handles only thin Mach-O slices, so it bails out cleanly
  on FAT magic and we record the skip rather than recursing slices here.
- We deliberately do NOT call analyze_ipa from here — the standalone
  contract is "single binary in, model out, no unpacking".
"""
from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo, BinaryFormat, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.android import _valid_r2_string, _valid_r2_function
from chimera.pipelines.common import _rehydrate_from_cache, r2_func_address

logger = logging.getLogger(__name__)


async def analyze_macho(
    macho_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Run the standalone Mach-O / FAT / dylib static analysis pipeline."""
    macho_path = Path(macho_path)

    # -----------------------------------------------------------------------
    # Phase 1: Triage cache check
    # -----------------------------------------------------------------------
    binary = BinaryInfo.from_path(macho_path)
    # _guess_platform already returns IOS for MACHO/FAT/DYLIB, but reassert
    # so a hand-constructed BinaryInfo upstream can't slip the wrong tuple
    # through (mirrors what pe.py and elf.py do).
    binary.platform = Platform.IOS
    sha = binary.sha256

    if cache.has(sha):
        cached = cache.get_json(sha, "triage")
        if cached:
            if cached.get("status") == "skipped":
                logger.warning(
                    "Cached analysis for %s was skipped: %s",
                    sha[:12], cached.get("reason", "unknown"),
                )
                model = UnifiedProgramModel(binary)
                try:
                    binary.framework = Framework(cached.get("framework", "none"))
                except ValueError:
                    binary.framework = Framework.NONE
                return model
            logger.info("Cache hit for %s — reusing triage", sha[:12])
            model = UnifiedProgramModel(binary)
            try:
                binary.framework = Framework(cached.get("framework", "native"))
            except ValueError:
                binary.framework = Framework.NATIVE
            _rehydrate_from_cache(model, cache, sha, language="objc", layer="native")
            return model

    # -----------------------------------------------------------------------
    # Phase 2: BinaryInfo + model setup
    # -----------------------------------------------------------------------
    model = UnifiedProgramModel(binary)
    binary.framework = Framework.NATIVE
    skipped_phases: list[str] = []
    is_fat = binary.format == BinaryFormat.FAT
    logger.info("Mach-O pipeline: %s [%s]", macho_path.name, binary.format.value)

    # -----------------------------------------------------------------------
    # Phase 3: r2 triage
    # -----------------------------------------------------------------------
    r2 = registry.get("radare2")
    if not (r2 and r2.is_available()):
        skipped_phases.append("radare2")
        logger.warning("radare2 unavailable — skipping native triage")
    else:
        try:
            async with resource_mgr.light():
                triage = await r2.analyze(str(macho_path), {"mode": "triage"})
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
                addr = r2_func_address(f) or "0x0"
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
            cache.put_json(sha, f"r2_{macho_path.name}", triage)
            logger.info(
                "r2: %d functions, %d strings",
                len(triage.get("functions", [])),
                len(triage.get("strings", [])),
            )
        except Exception as exc:
            logger.warning("radare2 phase failed: %s", exc)
            skipped_phases.append("radare2:error")

    # -----------------------------------------------------------------------
    # Phase 4: ObjC metadata parse (best-effort, skip FAT)
    # -----------------------------------------------------------------------
    if is_fat:
        # The ObjC parser expects a thin Mach-O. Routing each FAT slice
        # belongs in the IPA pipeline; here we record the skip and move on.
        skipped_phases.append("objc_metadata:fat_input")
    else:
        try:
            from chimera.parsers.macho_objc import parse_objc_metadata, ObjCParseError
            try:
                md = parse_objc_metadata(macho_path)
            except ObjCParseError as exc:
                logger.info("objc_metadata: not parseable (%s)", exc)
                skipped_phases.append("objc_metadata:parse_error")
            else:
                for cls in md.classes:
                    try:
                        model.add_objc_class(cls)
                    except Exception:
                        # add_objc_class is defensive but we never want a
                        # single bad class to abort the pipeline.
                        continue
                cache.put_json(sha, "objc_metadata", {
                    "class_count": len(md.classes),
                    "category_count": len(md.categories),
                    "protocol_count": len(md.protocols),
                    "chained_fixups_detected": md.chained_fixups_detected,
                    "skipped_pointers": md.skipped_pointers,
                })
                if md.classes:
                    logger.info(
                        "objc_metadata: %d classes, %d categories, %d protocols",
                        len(md.classes), len(md.categories), len(md.protocols),
                    )
        except Exception as exc:
            logger.warning("objc_metadata phase failed: %s", exc)
            skipped_phases.append("objc_metadata:error")

    # -----------------------------------------------------------------------
    # Phase 5: YARA
    # -----------------------------------------------------------------------
    try:
        from chimera.bypass.yara_scanner import scan_native_lib
        yara_result = await scan_native_lib(macho_path)
        cache.put_json(sha, f"yara_{macho_path.name}", yara_result)
        logger.info(
            "yara: %d crypto algorithms, packer=%s",
            len(yara_result.get("crypto_algorithms", [])),
            yara_result.get("commercial_packer"),
        )
    except Exception as exc:
        logger.warning("yara phase failed: %s", exc)
        skipped_phases.append("yara")

    # -----------------------------------------------------------------------
    # Phase 6: Capa
    # -----------------------------------------------------------------------
    capa = registry.get("capa")
    if not (capa and capa.is_available()):
        skipped_phases.append("capa:unavailable")
    else:
        try:
            async with resource_mgr.light():
                capa_result = await capa.analyze(str(macho_path), {})
            cache.put_json(sha, f"capa_{macho_path.name}", capa_result)
            logger.info("capa: %d capabilities",
                        len(capa_result.get("capabilities", [])))
        except Exception as exc:
            logger.warning("capa phase failed: %s", exc)
            skipped_phases.append("capa:error")

    # -----------------------------------------------------------------------
    # Phase 7: Final triage cache write
    # -----------------------------------------------------------------------
    cache.put_json(sha, "triage", {
        "platform": "ios",
        "format": binary.format.value,
        "framework": binary.framework.value,
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "import_count": len(model.imports),
        "skipped_phases": skipped_phases,
    })

    logger.info(
        "Mach-O analysis complete: %d functions, %d strings, %d imports",
        len(model.functions), len(model.get_strings()), len(model.imports),
    )
    return model
