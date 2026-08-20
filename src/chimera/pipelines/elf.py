"""Standalone Linux ELF analysis pipeline.

Phases
------
1.  Triage cache check — rehydrate and return if hit.
2.  BinaryInfo + model setup.
3.  ELF header parse — NEEDED libs → model.imports; security flags cached.
4.  r2 triage — functions + strings from native layer.
5.  Persistence-string scan — Linux-specific path heuristics.
6.  Syscall scoring — bucket annotation on symbol names.
7.  XOR-string heuristic — single-byte XOR decoding of raw file bytes.
8.  YARA — crypto constants + commercial packer detection.
9.  Capa — capability tags.
10. Ghidra deep — gated by config.ghidra_skip and file size.
11. Native protection scan — packer / anti-debug / anti-VM heuristics.
12. Final triage cache write.
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
from chimera.pipelines.common import (
    _rehydrate_from_cache,
    deepen_r2_functions,
    ingest_ghidra_functions,
    r2_func_address,
    should_deepen_r2,
)

logger = logging.getLogger(__name__)

_XOR_SIZE_LIMIT = 50 * 1024 * 1024   # 50 MB — skip heuristic above this
_XOR_CAP_BYTES   =  5 * 1024 * 1024   #  5 MB — read at most this much
_XOR_MIN_RUN     = 8                   # high-confidence: run length ≥ 8


async def analyze_elf(
    elf_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Run the full standalone Linux ELF static analysis pipeline."""
    elf_path = Path(elf_path)

    # -----------------------------------------------------------------------
    # Phase 1: Triage cache check
    # -----------------------------------------------------------------------
    binary = BinaryInfo.from_path(elf_path)
    # `model/binary.py:_detect_format` doesn't disambiguate Android-JNI ELF
    # from a standalone Linux ELF — the dispatcher in `pipelines/common.py`
    # already routed us here, so override the format/platform tuple to
    # match. Without this, downstream consumers (CLI summary, report)
    # display the misleading default (Platform.ANDROID).
    from chimera.model.binary import Platform
    binary.format = BinaryFormat.ELF_STANDALONE
    binary.platform = Platform.LINUX_NATIVE
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
    binary.framework = Framework.NATIVE
    logger.info("ELF pipeline: %s [%s]", elf_path.name, binary.format.value)

    # -----------------------------------------------------------------------
    # Phase 3: ELF header parse
    # -----------------------------------------------------------------------
    header = None
    try:
        from chimera.parsers.elf_header import parse_elf
        header = parse_elf(elf_path)

        # Add DT_NEEDED shared libraries as imports
        for lib_name in header.needed:
            model.add_import(ImportEntry(dll="", name=lib_name))

        cache.put_json(sha, "elf_header", {
            "file_class": header.file_class,
            "machine": header.machine,
            "e_type": header.e_type,
            "entry_point": hex(header.entry_point),
            "dynamic_linker": header.dynamic_linker,
            "needed": header.needed,
            "rpath": header.rpath,
            "runpath": header.runpath,
            "soname": header.soname,
            "relro": header.relro,
            "nx": header.nx,
            "pie": header.pie,
            "section_count": len(header.sections),
            "has_symbols": header.has_symbols,
            "is_stripped": header.is_stripped,
        })
        logger.info(
            "ELF header: machine=%s, %d NEEDED libs, relro=%s, pie=%s",
            header.machine, len(header.needed), header.relro, header.pie,
        )
    except Exception as exc:
        logger.warning("elf_header phase failed: %s", exc)
        skipped_phases.append("elf_header")

    # -----------------------------------------------------------------------
    # Phase 4: r2 triage
    # -----------------------------------------------------------------------
    r2 = registry.get("radare2")
    if not (r2 and r2.is_available()):
        skipped_phases.append("radare2")
        logger.warning("radare2 unavailable — skipping native triage")
    else:
        try:
            async with resource_mgr.light():
                triage = await r2.analyze(str(elf_path), {"mode": "triage"})
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
                    language="c",
                    classification="unknown",
                    layer="native",
                    source_backend="radare2",
                ))
            cache.put_json(sha, f"r2_{elf_path.name}", triage)
            logger.info(
                "r2: %d functions, %d strings",
                len(triage.get("functions", [])),
                len(triage.get("strings", [])),
            )
            # Stripped ELFs list ~nothing in the symbol table; escalate to r2's
            # analysis pass to actually recover functions.
            if should_deepen_r2(
                len(triage.get("functions", [])),
                deep=getattr(config, "r2_deep", False),
                min_functions=getattr(config, "r2_deep_min_functions", 3),
            ):
                try:
                    async with resource_mgr.heavy():
                        n_deep = await deepen_r2_functions(
                            r2, elf_path, model, cache=cache, sha256=sha,
                            cache_key=f"r2_deep_{elf_path.name}",
                        )
                    logger.info("r2 deep analysis recovered %d additional functions", n_deep)
                except Exception as exc:
                    logger.warning("r2 deep analysis failed: %s", exc)
        except Exception as exc:
            logger.warning("radare2 phase failed: %s", exc)
            skipped_phases.append("radare2")

    # -----------------------------------------------------------------------
    # Phase 5: Persistence-string scan
    # -----------------------------------------------------------------------
    try:
        from chimera.parsers.elf_persistence_scanner import scan_strings
        persistence_hits = scan_strings(model.get_strings())
        cache.put_json(sha, "elf_persistence", {
            "hit_count": len(persistence_hits),
            "hits": persistence_hits[:100],  # cap serialised output
        })
        if persistence_hits:
            logger.info(
                "persistence scanner: %d hits (%s, ...)",
                len(persistence_hits),
                persistence_hits[0]["category"],
            )
    except Exception as exc:
        logger.warning("elf_persistence phase failed: %s", exc)
        skipped_phases.append("elf_persistence")

    # -----------------------------------------------------------------------
    # Phase 5.5: FLIRT-equivalent function signature matching. Renames
    # statically-linked libc/openssl/zlib/curl functions in the model so
    # decompilation and call-graph views show recognisable names.
    # -----------------------------------------------------------------------
    if not getattr(config, "skip_sig_match", False):
        try:
            from chimera.parsers.function_signatures import match_functions
            sig_stats = match_functions(model, elf_path)
            cache.put_json(sha, "sig_match", sig_stats)
            if sig_stats["matched"]:
                logger.info("library signatures matched %d functions", sig_stats["matched"])
        except Exception as exc:
            logger.warning("signature matcher failed: %s", exc)
            skipped_phases.append("sig_match")

    # -----------------------------------------------------------------------
    # Phase 6: Syscall scoring
    # -----------------------------------------------------------------------
    try:
        from chimera.parsers.syscall_scoring import score_syscalls
        # Use function names from the model (r2 exposes symbol names here)
        symbols = [f.name for f in model.functions if f.name]
        syscall_buckets = score_syscalls(symbols)
        cache.put_json(sha, "elf_syscalls", syscall_buckets)
        if syscall_buckets:
            logger.info(
                "syscall scoring: %d suspicious buckets hit", len(syscall_buckets)
            )
    except Exception as exc:
        logger.warning("syscall_scoring phase failed: %s", exc)
        skipped_phases.append("elf_syscalls")

    # -----------------------------------------------------------------------
    # Phase 7: XOR-string heuristic (skip if file > 50 MB)
    # -----------------------------------------------------------------------
    try:
        file_size = elf_path.stat().st_size
        if file_size > _XOR_SIZE_LIMIT:
            skipped_phases.append(f"xor_strings:size>{_XOR_SIZE_LIMIT // (1024*1024)}MB")
            logger.info(
                "XOR heuristic skipped for %s (size=%d bytes)", elf_path.name, file_size
            )
        else:
            from chimera.parsers.xor_string_heuristic import find_xor_strings
            data = elf_path.read_bytes()[:_XOR_CAP_BYTES]
            xor_results = find_xor_strings(data)
            high_conf = [r for r in xor_results if _printable_run_length_min(r["value"]) >= _XOR_MIN_RUN]
            for r in high_conf:
                model.add_string(
                    address=hex(r["address"]),
                    value=r["value"],
                    section="xor_decoded",
                )
            cache.put_json(sha, "xor_strings", {
                "total_candidates": len(xor_results),
                "high_confidence": len(high_conf),
            })
            if high_conf:
                logger.info("XOR heuristic: %d high-confidence strings", len(high_conf))
    except Exception as exc:
        logger.warning("xor_strings phase failed: %s", exc)
        skipped_phases.append("xor_strings")

    # -----------------------------------------------------------------------
    # Phase 8: YARA
    # -----------------------------------------------------------------------
    try:
        from chimera.bypass.yara_scanner import scan_native_lib
        yara_result = await scan_native_lib(elf_path)
        cache.put_json(sha, f"yara_{elf_path.name}", yara_result)
        logger.info(
            "yara: %d crypto algorithms, packer=%s",
            len(yara_result.get("crypto_algorithms", [])),
            yara_result.get("commercial_packer"),
        )
    except Exception as exc:
        logger.warning("yara phase failed: %s", exc)
        skipped_phases.append("yara")

    # -----------------------------------------------------------------------
    # Phase 9: Capa
    # -----------------------------------------------------------------------
    capa = registry.get("capa")
    if not (capa and capa.is_available()):
        skipped_phases.append("capa:unavailable")
    else:
        try:
            async with resource_mgr.light():
                capa_result = await capa.analyze(str(elf_path), {})
            cache.put_json(sha, f"capa_{elf_path.name}", capa_result)
            logger.info("capa: %d capabilities",
                        len(capa_result.get("capabilities", [])))
        except Exception as exc:
            logger.warning("capa phase failed: %s", exc)
            skipped_phases.append("capa:error")

    # -----------------------------------------------------------------------
    # Phase 10: Ghidra deep (gated by config and size)
    # -----------------------------------------------------------------------
    if getattr(config, "ghidra_skip", False):
        skipped_phases.append("ghidra:config")
        logger.info("ghidra phase skipped via config")
    else:
        ghidra = registry.get("ghidra")
        if not (ghidra and ghidra.is_available()):
            skipped_phases.append("ghidra:unavailable")
            logger.warning("ghidra unavailable — skipping deep analysis")
        else:
            max_mb = getattr(config, "ghidra_max_lib_mb", 20)
            size_bytes = elf_path.stat().st_size
            if max_mb > 0 and size_bytes > max_mb * 1024 * 1024:
                skipped_phases.append(f"ghidra:size>{max_mb}MB")
                logger.info(
                    "ghidra skip %s (size=%d > %dMB)",
                    elf_path.name, size_bytes, max_mb,
                )
            else:
                try:
                    async with resource_mgr.heavy():
                        ghidra_result = await ghidra.analyze(
                            str(elf_path),
                            {
                                "mode": "decompile",
                                "project_dir": str(config.project_dir / "ghidra"),
                            },
                        )
                    cache.put_json(sha, f"ghidra_{elf_path.name}", ghidra_result)
                    n_dec = ingest_ghidra_functions(model, ghidra_result)
                    logger.info("ghidra: deep analysis complete (%d decompiled)", n_dec)
                except Exception as exc:
                    logger.warning("ghidra phase failed: %s", exc)
                    skipped_phases.append("ghidra:error")

    # -----------------------------------------------------------------------
    # Phase 11: Native protection scan
    # -----------------------------------------------------------------------
    if header is not None:
        try:
            from chimera.bypass.native_detector import scan_elf
            profile = scan_elf(model, header)
            cache.put_json(sha, "native_protection", {
                "packer": profile.packer,
                "has_anti_debug": profile.has_anti_debug,
                "anti_debug_low_confidence": profile.anti_debug_low_confidence,
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
    else:
        skipped_phases.append("native_protection:no_header")

    # -----------------------------------------------------------------------
    # Phase 12: Final triage cache write
    # -----------------------------------------------------------------------
    cache.put_json(sha, "triage", {
        "platform": "linux_native",
        "format": binary.format.value,
        "framework": binary.framework.value,
        "function_count": len(model.functions),
        "string_count": len(model.get_strings()),
        "import_count": len(model.imports),
        "skipped_phases": skipped_phases,
    })

    logger.info(
        "ELF analysis complete: %d functions, %d strings, %d imports",
        len(model.functions), len(model.get_strings()), len(model.imports),
    )
    return model


def _printable_run_length_min(value: str) -> int:
    """Return the length of the longest run of non-replacement printable chars."""
    best = current = 0
    for ch in value:
        if ch != "�" and (0x20 <= ord(ch) < 0x7f or ch in "\t\n"):
            current += 1
            if current > best:
                best = current
        else:
            current = 0
    return best
