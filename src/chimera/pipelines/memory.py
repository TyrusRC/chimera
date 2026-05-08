"""Linux memory-image analysis pipeline.

Phases
------
1.  Triage cache check — rehydrate and return if hit.
2.  BinaryInfo + model setup — force Platform.LINUX_MEMORY.
3.  Banner identification — linux.banner.Banners → kernel version string.
4.  pslist + pstree — process list and tree.
5.  bash — recovered bash history commands.
6.  netstat — open sockets (sockstat first, netstat fallback).
7.  malfind — VMA regions with suspicious permissions.
8.  lsmod + check_modules + check_syscall — kernel module / rootkit detection.
9.  Memory protection summary — high-level signal dict cached as memory_protection.
10. Final triage cache write.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryFormat, BinaryInfo, Platform
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private helper
# ---------------------------------------------------------------------------

async def _run_plugin(
    adapter: Any,
    image_path: Path,
    plugin_name: str,
    *,
    args: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """Invoke a single Volatility plugin; return a normalised result dict.

    If the adapter is unavailable, returns ``{"available": False, "rows": []}``.
    """
    if not adapter.is_available():
        return {"available": False, "plugin": plugin_name, "rows": []}
    options: dict = {"plugin": plugin_name, "timeout": timeout}
    if args:
        options["args"] = args
    return await adapter.analyze(str(image_path), options)


# ---------------------------------------------------------------------------
# Public pipeline entry-point
# ---------------------------------------------------------------------------

async def analyze_memory(
    image_path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Run the full Linux memory-image analysis pipeline."""
    image_path = Path(image_path)

    # -----------------------------------------------------------------------
    # Phase 1: Triage cache check
    # -----------------------------------------------------------------------
    binary = BinaryInfo.from_path(image_path)
    binary.platform = Platform.LINUX_MEMORY
    sha = binary.sha256

    if cache.has(sha):
        cached = cache.get_json(sha, "triage")
        if cached and cached.get("platform") == "linux_memory":
            logger.info("Cache hit for %s — reusing memory triage", sha[:12])
            model = UnifiedProgramModel(binary)
            return model

    # -----------------------------------------------------------------------
    # Phase 2: BinaryInfo + model setup
    # -----------------------------------------------------------------------
    # Correct the format for files whose magic was detected correctly but that
    # arrived via a suffix-based path (e.g. a .lime file whose magic wasn't
    # checked yet).
    if not binary.format.is_memory_image:
        binary.format = BinaryFormat.MEMORY_LIME
    binary.platform = Platform.LINUX_MEMORY

    model = UnifiedProgramModel(binary)
    skipped_phases: list[str] = []

    logger.info("Memory pipeline: %s [%s]", image_path.name, binary.format.value)

    # Obtain the Volatility adapter (may be absent / unavailable)
    vol = registry.get("volatility")

    # -----------------------------------------------------------------------
    # Phase 3: Banner identification
    # -----------------------------------------------------------------------
    kernel_banner: str | None = None
    try:
        if vol:
            result = await _run_plugin(vol, image_path, "linux.banner.Banners")
            rows = result.get("rows") or []
            cache.put_json(sha, "vol_banner", {"plugin": "linux.banner.Banners", "rows": rows})
            if rows:
                kernel_banner = (
                    rows[0].get("Banner")
                    or rows[0].get("banner")
                    or rows[0].get("KernelBanner")
                    or str(rows[0])
                )
                logger.info("Memory banner: %s", kernel_banner)
        else:
            skipped_phases.append("banner:no_adapter")
    except Exception as exc:
        logger.warning("banner phase failed: %s", exc)
        skipped_phases.append("banner:error")

    # -----------------------------------------------------------------------
    # Phase 4: pslist + pstree
    # -----------------------------------------------------------------------
    processes: list = []
    tree_roots: list = []
    try:
        if vol:
            from chimera.parsers.volatility_processes import parse_pslist, parse_pstree

            pslist_result = await _run_plugin(vol, image_path, "linux.pslist.PsList")
            pslist_rows = pslist_result.get("rows") or []
            processes = parse_pslist(pslist_rows)
            cache.put_json(sha, "vol_pslist", {
                "plugin": "linux.pslist.PsList",
                "rows": [p.to_dict() for p in processes],
            })

            pstree_result = await _run_plugin(vol, image_path, "linux.pstree.PsTree")
            pstree_rows = pstree_result.get("rows") or []
            tree_roots = parse_pstree(pstree_rows)
            cache.put_json(sha, "vol_pstree", {
                "plugin": "linux.pstree.PsTree",
                "rows": [r.to_dict() for r in tree_roots],
            })
            logger.info("pslist: %d processes; pstree: %d roots", len(processes), len(tree_roots))
        else:
            skipped_phases.append("pslist:no_adapter")
    except Exception as exc:
        logger.warning("pslist/pstree phase failed: %s", exc)
        skipped_phases.append("pslist:error")

    # -----------------------------------------------------------------------
    # Phase 5: bash
    # -----------------------------------------------------------------------
    bash_entries: list = []
    try:
        if vol:
            from chimera.parsers.volatility_artifacts import parse_bash

            bash_result = await _run_plugin(vol, image_path, "linux.bash.Bash")
            bash_rows = bash_result.get("rows") or []
            bash_entries = parse_bash(bash_rows)
            cache.put_json(sha, "vol_bash", {
                "plugin": "linux.bash.Bash",
                "rows": [e.to_dict() for e in bash_entries],
            })
            logger.info("bash: %d history entries", len(bash_entries))

            # Surface bash commands as model strings for downstream IoC / YARA
            for i, entry in enumerate(bash_entries):
                model.add_string(
                    address=hex(0x10000 + i),
                    value=entry.command,
                    section="memory_bash",
                )
        else:
            skipped_phases.append("bash:no_adapter")
    except Exception as exc:
        logger.warning("bash phase failed: %s", exc)
        skipped_phases.append("bash:error")

    # -----------------------------------------------------------------------
    # Phase 6: netstat (sockstat first, netstat fallback)
    # -----------------------------------------------------------------------
    connections: list = []
    try:
        if vol:
            from chimera.parsers.volatility_artifacts import parse_netstat

            sock_result = await _run_plugin(vol, image_path, "linux.sockstat.Sockstat")
            sock_rows = sock_result.get("rows") or []

            if sock_rows:
                connections = parse_netstat(sock_rows)
                cache.put_json(sha, "vol_netstat", {
                    "plugin": "linux.sockstat.Sockstat",
                    "rows": [c.to_dict() for c in connections],
                })
                logger.info("sockstat: %d connections", len(connections))
            else:
                # Fall back to the older netstat plugin
                net_result = await _run_plugin(vol, image_path, "linux.netstat.Netstat")
                net_rows = net_result.get("rows") or []
                connections = parse_netstat(net_rows)
                cache.put_json(sha, "vol_netstat", {
                    "plugin": "linux.netstat.Netstat",
                    "rows": [c.to_dict() for c in connections],
                })
                logger.info("netstat (fallback): %d connections", len(connections))
        else:
            skipped_phases.append("netstat:no_adapter")
    except Exception as exc:
        logger.warning("netstat phase failed: %s", exc)
        skipped_phases.append("netstat:error")

    # -----------------------------------------------------------------------
    # Phase 7: malfind
    # -----------------------------------------------------------------------
    malfind_hits: list = []
    try:
        if vol:
            from chimera.parsers.volatility_artifacts import parse_malfind

            mf_result = await _run_plugin(vol, image_path, "linux.malfind.Malfind")
            mf_rows = mf_result.get("rows") or []
            malfind_hits = parse_malfind(mf_rows)
            cache.put_json(sha, "vol_malfind", {
                "plugin": "linux.malfind.Malfind",
                "rows": [h.to_dict() for h in malfind_hits],
            })
            logger.info("malfind: %d hits", len(malfind_hits))

            # Add disassembly snippets to model strings if available
            for hit in malfind_hits:
                if hit.has_disasm and hit.notes:
                    model.add_string(
                        address=hit.start_addr,
                        value=hit.notes,
                        section="memory_malfind",
                    )
        else:
            skipped_phases.append("malfind:no_adapter")
    except Exception as exc:
        logger.warning("malfind phase failed: %s", exc)
        skipped_phases.append("malfind:error")

    # -----------------------------------------------------------------------
    # Phase 8: lsmod + check_modules + check_syscall
    # -----------------------------------------------------------------------
    kernel_modules: list = []
    module_anomalies: list = []
    syscall_hooks: list = []
    hooked_syscalls: list = []
    try:
        if vol:
            from chimera.parsers.volatility_kernel import (
                parse_check_modules,
                parse_check_syscall,
                parse_lsmod,
                filter_hooked_syscalls,
            )

            lsmod_result = await _run_plugin(vol, image_path, "linux.lsmod.Lsmod")
            lsmod_rows = lsmod_result.get("rows") or []
            kernel_modules = parse_lsmod(lsmod_rows)
            cache.put_json(sha, "vol_lsmod", {
                "plugin": "linux.lsmod.Lsmod",
                "rows": [m.to_dict() for m in kernel_modules],
            })

            cm_result = await _run_plugin(vol, image_path, "linux.check_modules.Check_modules")
            cm_rows = cm_result.get("rows") or []
            module_anomalies = parse_check_modules(cm_rows)
            cache.put_json(sha, "vol_check_modules", {
                "plugin": "linux.check_modules.Check_modules",
                "rows": [a.to_dict() for a in module_anomalies],
            })

            cs_result = await _run_plugin(vol, image_path, "linux.check_syscall.Check_syscall")
            cs_rows = cs_result.get("rows") or []
            syscall_hooks = parse_check_syscall(cs_rows)
            hooked_syscalls = filter_hooked_syscalls(syscall_hooks)
            cache.put_json(sha, "vol_check_syscall", {
                "plugin": "linux.check_syscall.Check_syscall",
                "rows": [h.to_dict() for h in syscall_hooks],
            })

            logger.info(
                "kernel: %d modules, %d hidden, %d hooked syscalls",
                len(kernel_modules), len(module_anomalies), len(hooked_syscalls),
            )
        else:
            skipped_phases.append("kernel:no_adapter")
    except Exception as exc:
        logger.warning("kernel phase failed: %s", exc)
        skipped_phases.append("kernel:error")

    # -----------------------------------------------------------------------
    # Phase 9: Memory protection summary
    # -----------------------------------------------------------------------
    try:
        kernel_thread_count = sum(1 for p in processes if p.is_kernel_thread)
        summary: dict = {
            "process_count": len(processes),
            "kernel_thread_count": kernel_thread_count,
            "bash_command_count": len(bash_entries),
            "network_connection_count": len(connections),
            "malfind_hit_count": len(malfind_hits),
            "kernel_module_count": len(kernel_modules),
            "hidden_module_count": len(module_anomalies),
            "hooked_syscall_count": len(hooked_syscalls),
            "kernel_banner": kernel_banner,
        }
        cache.put_json(sha, "memory_protection", summary)
        logger.info(
            "memory_protection: %d procs, %d malfind, %d hidden mods, %d hooked syscalls",
            summary["process_count"], summary["malfind_hit_count"],
            summary["hidden_module_count"], summary["hooked_syscall_count"],
        )
    except Exception as exc:
        logger.warning("memory_protection phase failed: %s", exc)
        skipped_phases.append("memory_protection:error")

    # -----------------------------------------------------------------------
    # Phase 10: Final triage cache write
    # -----------------------------------------------------------------------
    cache.put_json(sha, "triage", {
        "platform": "linux_memory",
        "format": binary.format.value,
        "process_count": len(processes),
        "bash_command_count": len(bash_entries),
        "malfind_hit_count": len(malfind_hits),
        "kernel_module_count": len(kernel_modules),
        "hidden_module_count": len(module_anomalies),
        "hooked_syscall_count": len(hooked_syscalls),
        "string_count": len(model.get_strings()),
        "skipped_phases": skipped_phases,
        "kernel_banner": kernel_banner,
    })

    logger.info(
        "Memory analysis complete: %d procs, %d strings, skipped=%s",
        len(processes), len(model.get_strings()), skipped_phases,
    )
    return model
