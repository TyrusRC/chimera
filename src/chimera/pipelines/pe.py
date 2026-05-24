"""Windows PE analysis pipeline.

Phases
------
1.  Triage cache check — rehydrate and return if hit.
2.  BinaryInfo + model setup.
3.  PE header parse — imports, sections, flags.
4.  CLR detection branch — route DOTNET_PE to ILSpy instead of Ghidra/FLOSS.
5.  r2 triage — functions + strings from native layer.
6.  Import scoring — bucket annotation on ImportEntry objects.
7.  PE flags — boolean security facts cached as `pe_flags`.
8.  FLOSS — decoded/decrypted strings (skipped for DOTNET_PE or by config).
9.  YARA — crypto constants + commercial packer detection.
10. Capa — capability tags.
11. Ghidra deep — skipped for DOTNET_PE and by config/size gate.
12. ILSpy — only for DOTNET_PE.
13. Native protection scan — packer / anti-debug / anti-VM heuristics.
14. Triage cache write.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo, BinaryFormat, Framework
from chimera.model.function import FunctionInfo, ImportEntry
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.android import _valid_r2_string, _valid_r2_function
from chimera.pipelines.common import _rehydrate_from_cache

logger = logging.getLogger(__name__)


async def analyze_pe(
    pe_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Run the full Windows PE static analysis pipeline."""
    pe_path = Path(pe_path)

    # -----------------------------------------------------------------------
    # Phase 1: Triage cache check
    # -----------------------------------------------------------------------
    binary = BinaryInfo.from_path(pe_path)
    # Force the platform tuple for PE-family inputs — `_detect_format`
    # already classified the format correctly via magic bytes, but
    # `_guess_platform`'s mapping is the authoritative source for the
    # CLI summary line.
    from chimera.model.binary import Platform, Architecture
    binary.platform = Platform.WINDOWS
    if binary.format == BinaryFormat.PE32 and binary.arch == Architecture.UNKNOWN:
        binary.arch = Architecture.X86
    elif binary.format in (BinaryFormat.PE64, BinaryFormat.DOTNET_PE) and binary.arch == Architecture.UNKNOWN:
        binary.arch = Architecture.X86_64
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
            _rehydrate_from_cache(model, cache, sha, language="c", layer="native")
            return model

    # -----------------------------------------------------------------------
    # Phase 2: BinaryInfo + model setup
    # -----------------------------------------------------------------------
    model = UnifiedProgramModel(binary)
    skipped_phases: list[str] = []
    is_dotnet = binary.format == BinaryFormat.DOTNET_PE
    logger.info("PE pipeline: %s [%s]", pe_path.name, binary.format.value)

    # -----------------------------------------------------------------------
    # Phase 3: PE header parse
    # -----------------------------------------------------------------------
    header = None
    try:
        from chimera.parsers.pe_header import parse_pe
        header = parse_pe(pe_path)

        # Populate imports
        for d in header.imports:
            entry = ImportEntry(
                dll=d.get("dll", ""),
                name=d.get("name", ""),
                address=d.get("address"),
                ordinal=d.get("ordinal"),
            )
            model.add_import(entry)

        # Cache a header summary
        cache.put_json(sha, "pe_header", {
            "machine": header.machine,
            "is_dll": header.is_dll,
            "is_dotnet": header.is_dotnet,
            "pe_class": header.pe_class,
            "timestamp": header.timestamp,
            "entry_point": hex(header.entry_point),
            "image_base": hex(header.image_base),
            "section_count": len(header.sections),
            "import_count": len(header.imports),
            "export_count": len(header.exports),
        })
        logger.info("PE header: %d imports, %d sections, dotnet=%s",
                    len(header.imports), len(header.sections), header.is_dotnet)
    except Exception as exc:
        logger.warning("pe_header phase failed: %s", exc)
        skipped_phases.append("pe_header")

    # -----------------------------------------------------------------------
    # Phase 4: CLR detection — set framework
    # -----------------------------------------------------------------------
    if is_dotnet or (header is not None and header.is_dotnet):
        is_dotnet = True
        # No Framework.DOTNET exists yet; use NATIVE as placeholder.
        binary.framework = Framework.NATIVE
        logger.info("CLR/.NET PE detected — routing to ILSpy; Ghidra/FLOSS skipped")
    else:
        binary.framework = Framework.NATIVE

    # -----------------------------------------------------------------------
    # Phase 5: r2 triage
    # -----------------------------------------------------------------------
    r2 = registry.get("radare2")
    if not (r2 and r2.is_available()):
        skipped_phases.append("radare2")
        logger.warning("radare2 unavailable — skipping native triage")
    else:
        try:
            async with resource_mgr.light():
                triage = await r2.analyze(str(pe_path), {"mode": "triage"})
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
                    language="c",
                    classification="unknown",
                    layer="native",
                    source_backend="radare2",
                ))
            cache.put_json(sha, f"r2_{pe_path.name}", triage)
            logger.info("r2: %d functions, %d strings",
                        len(triage.get("functions", [])),
                        len(triage.get("strings", [])))
        except Exception as exc:
            logger.warning("radare2 phase failed: %s", exc)
            skipped_phases.append("radare2")

    # -----------------------------------------------------------------------
    # Phase 6: Import scoring
    # -----------------------------------------------------------------------
    if not getattr(config, "skip_pe_imports", False) and header is not None:
        try:
            from chimera.parsers.import_scoring import score_imports

            # Build a mutable list mirroring the model's imports for in-place mutation
            import_dicts = [
                {"name": e.name, "dll": e.dll, "address": e.address, "ordinal": e.ordinal}
                for e in model.imports
            ]
            bucket_summary = score_imports(import_dicts)

            # Copy buckets back onto ImportEntry objects by position
            live_imports = model._imports
            for entry, d in zip(live_imports, import_dicts):
                bucket = d.get("bucket")
                if bucket:
                    entry.bucket = bucket

            cache.put_json(sha, "pe_imports", {
                "bucket_summary": bucket_summary,
                "scored_count": sum(
                    v["score"] for v in bucket_summary.values()
                ),
            })
            logger.info("import scoring: %d buckets hit", len(bucket_summary))
        except Exception as exc:
            logger.warning("import_scoring phase failed: %s", exc)
            skipped_phases.append("import_scoring")

    # -----------------------------------------------------------------------
    # Phase 6.5: FLIRT-equivalent function signature matching.
    # Walks the model's functions and tags statically-linked libc/openssl/
    # zlib/curl matches in-place. Best-effort — silently no-ops when the
    # signature pack is empty or the binary's arch isn't represented.
    # -----------------------------------------------------------------------
    if not getattr(config, "skip_sig_match", False):
        try:
            from chimera.parsers.function_signatures import match_functions
            sig_stats = match_functions(model, pe_path)
            cache.put_json(sha, "sig_match", sig_stats)
            if sig_stats["matched"]:
                logger.info("library signatures matched %d functions", sig_stats["matched"])
        except Exception as exc:
            logger.warning("signature matcher failed: %s", exc)
            skipped_phases.append("sig_match")

    # -----------------------------------------------------------------------
    # Phase 7: PE flags
    # -----------------------------------------------------------------------
    if header is not None:
        try:
            writable_executable = sum(
                1 for s in header.sections
                if s.is_writable and s.is_executable
            )
            high_entropy = sum(
                1 for s in header.sections if s.entropy > 7.0
            )
            cache.put_json(sha, "pe_flags", {
                "has_authenticode_signature": header.has_authenticode_signature,
                "has_tls_callbacks": header.has_tls_callbacks,
                "writable_executable_sections": writable_executable,
                "high_entropy_section_count": high_entropy,
                "is_dll": header.is_dll,
                "pe_class": header.pe_class,
            })
        except Exception as exc:
            logger.warning("pe_flags phase failed: %s", exc)
            skipped_phases.append("pe_flags")

    # -----------------------------------------------------------------------
    # Phase 8: FLOSS (skipped for DOTNET_PE and by config)
    # -----------------------------------------------------------------------
    if is_dotnet:
        skipped_phases.append("floss:dotnet_pe")
    elif getattr(config, "skip_floss", False):
        skipped_phases.append("floss:config")
    else:
        floss = registry.get("floss")
        if not (floss and floss.is_available()):
            skipped_phases.append("floss:unavailable")
            logger.debug("floss unavailable — skipping decoded strings")
        else:
            try:
                timeout = getattr(config, "floss_timeout", 90)
                async with resource_mgr.light():
                    floss_result = await floss.analyze(
                        str(pe_path), {"timeout": timeout}
                    )
                for s in floss_result.get("decoded_strings", []):
                    if not isinstance(s, dict):
                        continue
                    val = s.get("string") or s.get("value")
                    if not val:
                        continue
                    model.add_string(
                        address=str(s.get("address", "0x0")),
                        value=val,
                        section="floss_decoded",
                    )
                logger.info("floss: %d decoded strings",
                            len(floss_result.get("decoded_strings", [])))
            except Exception as exc:
                logger.warning("floss phase failed: %s", exc)
                skipped_phases.append("floss:error")

    # -----------------------------------------------------------------------
    # Phase 9: YARA
    # -----------------------------------------------------------------------
    try:
        from chimera.bypass.yara_scanner import scan_native_lib
        yara_result = await scan_native_lib(pe_path)
        cache.put_json(sha, f"yara_{pe_path.name}", yara_result)
        logger.info(
            "yara: %d crypto algorithms, packer=%s",
            len(yara_result.get("crypto_algorithms", [])),
            yara_result.get("commercial_packer"),
        )
    except Exception as exc:
        logger.warning("yara phase failed: %s", exc)
        skipped_phases.append("yara")

    # -----------------------------------------------------------------------
    # Phase 10: Capa
    # -----------------------------------------------------------------------
    capa = registry.get("capa")
    if not (capa and capa.is_available()):
        skipped_phases.append("capa:unavailable")
    else:
        try:
            async with resource_mgr.light():
                capa_result = await capa.analyze(str(pe_path), {})
            cache.put_json(sha, f"capa_{pe_path.name}", capa_result)
            logger.info("capa: %d capabilities",
                        len(capa_result.get("capabilities", [])))
        except Exception as exc:
            logger.warning("capa phase failed: %s", exc)
            skipped_phases.append("capa:error")

    # -----------------------------------------------------------------------
    # Phase 11: Ghidra deep (skipped for DOTNET_PE and by config/size gate)
    # -----------------------------------------------------------------------
    if is_dotnet:
        skipped_phases.append("ghidra:dotnet_pe")
    elif getattr(config, "ghidra_skip", False):
        skipped_phases.append("ghidra:config")
        logger.info("ghidra phase skipped via config")
    else:
        ghidra = registry.get("ghidra")
        if not (ghidra and ghidra.is_available()):
            skipped_phases.append("ghidra:unavailable")
            logger.warning("ghidra unavailable — skipping deep analysis")
        else:
            max_mb = getattr(config, "ghidra_max_lib_mb", 20)
            size_bytes = pe_path.stat().st_size
            if max_mb > 0 and size_bytes > max_mb * 1024 * 1024:
                skipped_phases.append(
                    f"ghidra:size>{max_mb}MB"
                )
                logger.info(
                    "ghidra skip %s (size=%d > %dMB)", pe_path.name,
                    size_bytes, max_mb,
                )
            else:
                try:
                    async with resource_mgr.heavy():
                        ghidra_result = await ghidra.analyze(
                            str(pe_path),
                            {
                                "mode": "decompile",
                                "project_dir": str(config.project_dir / "ghidra"),
                            },
                        )
                    cache.put_json(sha, f"ghidra_{pe_path.name}", ghidra_result)
                    logger.info("ghidra: deep analysis complete")
                except Exception as exc:
                    logger.warning("ghidra phase failed: %s", exc)
                    skipped_phases.append("ghidra:error")

    # -----------------------------------------------------------------------
    # Phase 12: ILSpy (only for DOTNET_PE)
    # -----------------------------------------------------------------------
    if is_dotnet and not getattr(config, "skip_ilspy", False):
        ilspy = registry.get("ilspy")
        if not (ilspy and ilspy.is_available()):
            skipped_phases.append("ilspy:unavailable")
            logger.warning("ilspy unavailable — skipping .NET decompilation")
        else:
            try:
                ilspy_output = config.project_dir / "ilspy" / sha[:12]
                async with resource_mgr.light():
                    ilspy_result = await ilspy.analyze(
                        str(pe_path),
                        {"output_dir": str(ilspy_output)},
                    )
                for t in ilspy_result.get("types", []):
                    type_name = t.get("name") or t.get("type_name", "Unknown")
                    addr = t.get("address") or f"ilspy_{type_name}"
                    model.add_function(FunctionInfo(
                        address=addr,
                        name=type_name,
                        original_name=type_name,
                        language="csharp",
                        classification="unknown",
                        layer="dotnet",
                        source_backend="ilspy",
                        decompiled=t.get("decompiled"),
                    ))
                cache.put_json(sha, f"ilspy_{pe_path.name}", ilspy_result)
                logger.info("ilspy: %d types decompiled",
                            len(ilspy_result.get("types", [])))
            except Exception as exc:
                logger.warning("ilspy phase failed: %s", exc)
                skipped_phases.append("ilspy:error")

    # -----------------------------------------------------------------------
    # Phase 13: Native protection scan
    # -----------------------------------------------------------------------
    if header is not None:
        try:
            from chimera.bypass.native_detector import scan_pe
            profile = scan_pe(model, header)
            cache.put_json(sha, "native_protection", {
                "packer": profile.packer,
                "has_anti_debug": profile.has_anti_debug,
                "has_anti_vm": profile.has_anti_vm,
                "has_self_inject": profile.has_self_inject,
                "has_persistence_strings": profile.has_persistence_strings,
                "obfuscation": profile.obfuscation,
                "syscall_buckets": profile.syscall_buckets,
                "high_entropy_section_count": profile.high_entropy_section_count,
                "details": profile.details[:50],
            })
        except Exception as exc:
            logger.warning("native_protection phase failed: %s", exc)
            skipped_phases.append("native_protection")

    # -----------------------------------------------------------------------
    # Phase 14: Final triage cache write
    # -----------------------------------------------------------------------
    cache.put_json(sha, "triage", {
        "platform": "windows",
        "format": binary.format.value,
        "framework": binary.framework.value,
        "is_dotnet": is_dotnet,
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "import_count": len(model.imports),
        "skipped_phases": skipped_phases,
    })

    logger.info(
        "PE analysis complete: %d functions, %d strings, %d imports",
        len(model.functions), len(model.get_strings()), len(model.imports),
    )
    return model
