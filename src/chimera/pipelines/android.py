"""Android APK analysis pipeline — orchestrates unpack, triage, decompile, map."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryInfo, Framework
from chimera.model.function import FunctionInfo, ImportEntry
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import (
    _rehydrate_from_cache,
    detect_kotlin,
    find_mapping_file,
    ingest_ghidra_functions,
    unpack_apk,
)
from chimera.pipelines.react_native import analyze_react_native_bundle, find_rn_bundle

logger = logging.getLogger(__name__)


def _jadx_sources_available(jadx_sources) -> bool:
    """True iff jadx_sources is a real Path that exists on disk."""
    return jadx_sources is not None and Path(jadx_sources).exists()


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
                try:
                    binary.framework = Framework(cached_triage.get("framework", "none"))
                except ValueError:
                    binary.framework = Framework.NONE
                return model
            logger.info("Cache hit for %s - reusing triage", binary.sha256[:12])
            model = UnifiedProgramModel(binary)
            try:
                binary.framework = Framework(cached_triage.get("framework", "native"))
            except ValueError:
                binary.framework = Framework.NATIVE
            _rehydrate_from_cache(model, cache, binary.sha256, language="c", layer="native")
            return model

    model = UnifiedProgramModel(binary)
    skipped_phases: list[str] = []
    kotlin_detected = False
    mapping_path: Path | None = None

    # Phase 1: Unpack
    logger.info("Unpacking APK")
    unpack_dir = config.project_dir / "unpacked" / binary.sha256[:12]
    unpack_result = unpack_apk(apk_path, unpack_dir)

    # Phase 2: Framework detection
    from chimera.frameworks.detector import FrameworkDetector
    detect_dir = unpack_result["output_dir"]
    detected = FrameworkDetector.detect(detect_dir)
    try:
        binary.framework = Framework(detected.framework)
    except ValueError:
        binary.framework = Framework.NONE
    logger.info("Framework detected: %s%s",
                detected.framework,
                f" ({detected.variant})" if detected.variant else "")

    # Phase 2.5: React Native sub-pipeline
    react_native_context: dict | None = None
    if binary.framework == Framework.REACT_NATIVE:
        rn_bundle_path = find_rn_bundle(unpack_result["output_dir"], "android")
        if rn_bundle_path is not None:
            logger.info("RN sub-pipeline on bundle: %s", rn_bundle_path)
            react_native_context = await analyze_react_native_bundle(
                bundle_path=rn_bundle_path,
                platform="android",
                model=model,
                registry=registry,
                cache=cache,
                sha=binary.sha256,
                output_root=config.project_dir / "rn_decompile",
            )
        else:
            react_native_context = {"bundle_path": None, "skipped_reason": "no_bundle_found"}

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

        # Aggregate native-side findings across libs.
        crypto_algos: set[str] = set()
        commercial_packer: str | None = None
        obfuscation_techniques: set[str] = set()
        capabilities: list[dict] = []

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
                # Surface native imports per-lib so the model carries them
                # — PE/ELF pipelines already do this; without it the report
                # has no view of native-side dependencies for mobile.
                for imp in triage.get("imports", []) or []:
                    name = imp.get("name") or imp.get("realname")
                    if not name:
                        continue
                    vaddr = imp.get("plt") or imp.get("vaddr") or 0
                    model.add_import(ImportEntry(
                        dll=lib_path.name,
                        name=str(name),
                        address=hex(vaddr) if isinstance(vaddr, int) and vaddr else None,
                        ordinal=imp.get("ordinal"),
                    ))
                cache.put_json(binary.sha256, f"r2_{lib_path.name}", triage)

        await asyncio.gather(*[_r2_triage(lib) for lib in unpack_result["native_libs"]])

        # Phase 4.5: Native-crypto / packer / capa / OLLVM detectors. Each
        # adapter is best-effort and silently degrades when its tool is
        # missing. The aggregated result lands in ProtectionProfile fields.
        from chimera.bypass.ollvm_detector import detect_ollvm_in_disasm, summarize as _ollvm_sum
        from chimera.bypass.yara_scanner import scan_native_lib

        capa = registry.get("capa")

        async def _native_protections(lib_path: Path) -> None:
            yara_result = await scan_native_lib(lib_path)
            for algo in yara_result.get("crypto_algorithms", []):
                crypto_algos.add(algo)
            nonlocal commercial_packer
            if yara_result.get("commercial_packer") and not commercial_packer:
                commercial_packer = yara_result["commercial_packer"]

            if capa and capa.is_available():
                async with resource_mgr.light():
                    capa_result = await capa.analyze(str(lib_path), {})
                for cap in capa_result.get("capabilities", []):
                    if cap.get("is_library"):
                        continue
                    capabilities.append({
                        "lib": lib_path.name,
                        "rule": cap["rule"],
                        "namespace": cap.get("namespace", ""),
                        "address_count": cap.get("address_count", 0),
                    })
                cache.put_json(binary.sha256, f"capa_{lib_path.name}", capa_result)

            cache.put_json(binary.sha256, f"yara_{lib_path.name}", yara_result)

            # OLLVM heuristic — needs r2 disasm. Run a second r2 pass in
            # the heavier `triage_with_disasm` mode so we have per-function
            # ops. Skip for libs over 2 MB to keep runtime bounded.
            if lib_path.stat().st_size <= 2 * 1024 * 1024:
                async with resource_mgr.light():
                    try:
                        deeper = await r2.analyze(str(lib_path),
                                                  {"mode": "triage_with_disasm"})
                    except (OSError, RuntimeError) as exc:
                        logger.debug("r2 deep pass failed for %s: %s", lib_path, exc)
                        return
                ollvm_findings = detect_ollvm_in_disasm(
                    deeper.get("per_function_disasm") or {})
                for tech, count in _ollvm_sum(ollvm_findings).items():
                    obfuscation_techniques.add(tech)
                    logger.info("OLLVM heuristic: %s x%d in %s",
                                tech, count, lib_path.name)
                if ollvm_findings:
                    cache.put_json(binary.sha256, f"ollvm_{lib_path.name}", {
                        "summary": _ollvm_sum(ollvm_findings),
                        "findings": [
                            {
                                "function": f.function, "address": f.address,
                                "technique": f.technique, "score": f.score,
                                "detail": f.detail,
                            }
                            for f in ollvm_findings[:200]
                        ],
                    })

        await asyncio.gather(
            *[_native_protections(lib) for lib in unpack_result["native_libs"]],
        )

        if crypto_algos or commercial_packer or obfuscation_techniques or capabilities:
            cache.put_json(binary.sha256, "native_protections", {
                "crypto_algorithms": sorted(crypto_algos),
                "commercial_packer": commercial_packer,
                "obfuscation_techniques": sorted(obfuscation_techniques),
                "capabilities": capabilities[:200],
            })

    # Phase 5: Decompile with jadx
    if not (jadx and jadx.is_available()):
        skipped_phases.append("jadx")
        logger.warning("jadx unavailable — skipping decompile")
    else:
        mapping_path = find_mapping_file(unpack_result["output_dir"], apk_path=apk_path)
        # Explicit override from config beats auto-discovery
        if getattr(config, "mapping_file", None):
            cfg_override = Path(config.mapping_file)
            if cfg_override.exists():
                mapping_path = cfg_override
        kotlin_detected = detect_kotlin(unpack_result["output_dir"])
        if mapping_path:
            logger.info("mapping file discovered: %s", mapping_path)
        if kotlin_detected:
            logger.info("kotlin metadata detected — enabling kotlin-aware flags")

        logger.info("jadx decompilation")
        jadx_output = config.project_dir / "jadx" / binary.sha256[:12]
        jadx_input = unpack_result.get("base_apk_path", apk_path)
        async with resource_mgr.light():
            jadx_result = await jadx.analyze(str(jadx_input), {
                "output_dir": str(jadx_output),
                "mapping_file": str(mapping_path) if mapping_path else None,
                "kotlin_aware": kotlin_detected,
                "deobf_cache_dir": str(config.cache_dir / "jadx_deobf" / binary.sha256[:12]),
            })
            cache.put_json(binary.sha256, "jadx", {
                "decompiled_files": jadx_result.get("decompiled_files", 0),
                "packages": jadx_result.get("packages", []),
                "sources_dir": jadx_result.get("sources_dir"),
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

        # Phase 5.5: ingest decompiled classes AND methods into the unified
        # model so downstream consumers (sdks, report, callgraph, cross-layer
        # linker) see the JVM layer. Without this, model.functions only ever
        # holds the few native funcs r2 surfaced, and tools that read it look
        # broken on every Android app that's mostly Java/Kotlin.
        if jadx_sources.exists():
            from chimera.pipelines.jvm_ingest import (
                ingest_jadx_classes,
                ingest_jadx_methods,
            )
            classes_added, strings_added = ingest_jadx_classes(model, jadx_sources)
            logger.info("ingested %d classes / %d strings from jadx",
                        classes_added, strings_added)
            if not config.skip_jvm_methods:
                methods_added = ingest_jadx_methods(model, jadx_sources)
                logger.info("ingested %d methods from jadx", methods_added)

    if manifest_xml is None:
        logger.warning("AndroidManifest.xml is binary-encoded. Install jadx for proper manifest analysis.")

    # Store decoded manifest in cache for MCP access
    if manifest_xml:
        cache.put(binary.sha256, "manifest_xml", manifest_xml.encode())

    # Cache referenced network_security_config.xml so the manifest_findings
    # detector can read it on demand without re-running jadx.
    if manifest_xml:
        try:
            from chimera.parsers.android_manifest import parse_manifest as _pm
            _manifest_tmp = jadx_output / "resources" / "AndroidManifest.xml"
            if _manifest_tmp.exists():
                _model = _pm(_manifest_tmp)
                nsc_ref = _model.application.network_security_config
                if nsc_ref and nsc_ref.startswith("@xml/"):
                    nsc_name = nsc_ref.split("/", 1)[1]
                    nsc_path = jadx_output / "resources" / "res" / "xml" / f"{nsc_name}.xml"
                    if nsc_path.exists():
                        cache.put(binary.sha256, "nsc_xml", nsc_path.read_bytes())
                        logger.info("nsc: cached %s", nsc_path.name)
        except Exception as e:
            logger.warning("nsc cache step failed: %s", e)

    # Phase 6: Ghidra deep analysis on native libraries.
    # Ghidra serializes per-lib (the global heavy semaphore) and is by
    # far the slowest backend on modern apps. We honor caps from config
    # so an analyst can keep analyze under a budget on multi-lib RN/Matrix
    # builds. Libs over `ghidra_max_lib_mb` and any beyond
    # `ghidra_max_libs` are still scanned by r2/YARA/OLLVM — they just
    # skip the slow decompile pass.
    ghidra_skipped_libs: list[tuple[str, str]] = []
    ghidra = registry.get("ghidra")
    if config.ghidra_skip:
        skipped_phases.append("ghidra")
        logger.info("ghidra phase skipped via config")
    elif not (ghidra and ghidra.is_available() and unpack_result["has_native"]):
        if unpack_result["has_native"]:
            skipped_phases.append("ghidra")
            logger.warning("ghidra unavailable — skipping deep analysis")
    else:
        max_mb = config.ghidra_max_lib_mb
        max_libs = config.ghidra_max_libs
        size_threshold = max_mb * 1024 * 1024 if max_mb > 0 else 0

        # Stable sort: smallest-first so we maximize the number of libs that
        # finish within the budget when there's a hard cap.
        sorted_libs = sorted(unpack_result["native_libs"], key=lambda p: p.stat().st_size)
        eligible: list[Path] = []
        for lib in sorted_libs:
            size = lib.stat().st_size
            if size_threshold and size > size_threshold:
                ghidra_skipped_libs.append((lib.name, f"size>{max_mb}MB"))
                continue
            if max_libs and len(eligible) >= max_libs:
                ghidra_skipped_libs.append((lib.name, f"max_libs={max_libs} reached"))
                continue
            eligible.append(lib)

        if ghidra_skipped_libs:
            for name, reason in ghidra_skipped_libs:
                logger.info("ghidra skip %s (%s)", name, reason)

        logger.info("Ghidra deep analysis on %d/%d native libraries",
                    len(eligible), len(unpack_result["native_libs"]))

        async def _ghidra_analyze(lib_path: Path) -> None:
            async with resource_mgr.heavy():
                ghidra_result = await ghidra.analyze(str(lib_path), {
                    "mode": "decompile",
                    "project_dir": str(config.project_dir / "ghidra"),
                })
                cache.put_json(binary.sha256, f"ghidra_{lib_path.name}", ghidra_result)
                ingest_ghidra_functions(model, ghidra_result)

        await asyncio.gather(*[_ghidra_analyze(lib) for lib in eligible])

    jni_result = None
    # Phase 6.5: cross-layer linker. Connects JVM native methods to
    # `Java_*` exports in the analyzed native libs.
    try:
        from chimera.pipelines.cross_layer import (
            collect_native_exports_from_cache, link_jni_static,
        )
        lib_keys = [k for k in cache.list_keys(binary.sha256)
                    if k.startswith("r2_") and k != "r2_triage"]
        if lib_keys:
            exports = collect_native_exports_from_cache(
                cache, binary.sha256, lib_keys,
            )
            jni_result = link_jni_static(model, exports)
            logger.info("jni-static: %d edges, %d unresolved",
                        jni_result.static_edges, jni_result.unresolved)
            # Phase 6.6: scan Java sources for callers of native methods
            if _jadx_sources_available(jadx_sources) and not config.skip_jvm_methods:
                from chimera.parsers.jvm_methods import (
                    find_callsites, parse_jvm_methods,
                )
                from chimera.pipelines.cross_layer import link_jvm_callsites
                methods = parse_jvm_methods(jadx_sources)
                native_names = {
                    m.name for m in methods if m.is_native
                }
                callsites = find_callsites(methods, native_names)
                cs_edges = link_jvm_callsites(model, callsites)
                jni_result.callsite_edges = cs_edges
                logger.info("jvm callsites: %d edges", cs_edges)
            # Phase 6.7: best-effort dynamic JNI binding recovery. Iterates
            # cached r2 disasm per lib, finds RegisterNatives callsites, and
            # walks register state to recover the JNINativeMethod table.
            # The class_fqcn is recovered from the static-binding pass when
            # available; otherwise we skip the entry. Highly obfuscated
            # binders are expected to fail — we count them as unresolved.
            try:
                from chimera.parsers.jni_register_natives import (
                    find_register_natives_calls,
                )
                dynamic_unresolved = 0
                for key in lib_keys:
                    blob = cache.get_json(binary.sha256, key) or {}
                    pfd = blob.get("per_function_disasm") or {}
                    calls = find_register_natives_calls(pfd)
                    if calls:
                        jni_result.unresolved += len(calls)
                        dynamic_unresolved += len(calls)
                # No FQCN heuristic yet, so dynamic_edges stays 0 — every site
                # counts as unresolved. Surface the count so the missing feature
                # is visible in logs.
                jni_result.dynamic_edges = 0
                if dynamic_unresolved:
                    logger.info(
                        "dynamic JNI: %d RegisterNatives callsites detected, "
                        "all unresolved (FQCN recovery not implemented)",
                        dynamic_unresolved,
                    )
            except Exception as exc:
                logger.warning("dynamic JNI linker failed: %s", exc)
    except Exception as exc:
        logger.warning("cross-layer linker failed: %s", exc)

    if jni_result is not None:
        cache.put_json(binary.sha256, "jni_summary", {
            "static": jni_result.static_edges,
            "dynamic": jni_result.dynamic_edges,
            "callsites": jni_result.callsite_edges,
            "unresolved": jni_result.unresolved,
        })

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
        "ghidra_skipped_libs": [
            {"lib": name, "reason": reason} for name, reason in ghidra_skipped_libs
        ],
        "jadx_context": {
            "kotlin_detected": kotlin_detected,
            "mapping_used": mapping_path is not None,
            "mapping_source": str(mapping_path) if mapping_path else None,
        },
        "react_native_context": react_native_context,
    })

    logger.info("Analysis complete: %d functions, %d strings",
                len(model.functions), len(model.get_strings()))
    return model
