"""Static-analysis and model-query tools.

Everything that reads the currently loaded binary: triage, functions,
strings, manifests, protections, framework/SDK detection.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    engine = mcpstate.get_engine()
    if name == "status":
        available = [a.name() for a in engine.registry.all_available()]
        unavailable = [a.name() for a in engine.registry.all_registered() if not a.is_available()]
        result = {
            "loaded": mcpstate.current_model is not None,
            "backends_available": available,
            "backends_missing": unavailable,
        }
        if mcpstate.current_model:
            b = mcpstate.current_model.binary
            result.update({
                "binary": b.path.name,
                "platform": b.platform.value,
                "framework": b.framework.value,
                "sha256": b.sha256[:16],
                "functions": len(mcpstate.current_model.functions),
                "strings": len(mcpstate.current_model.get_strings()),
                "analysis_config": mcpstate.analysis_config,
            })
            # Active Frida sessions
            frida = engine.registry.get("frida")
            if frida and hasattr(frida, "active_sessions"):
                result["frida_sessions"] = frida.active_sessions()
            # Active fuzzing campaigns
            afl = engine.registry.get("afl++")
            if afl and hasattr(afl, "_campaigns"):
                result["fuzz_campaigns"] = [
                    {"id": c.campaign_id, "status": c.status}
                    for c in afl._campaigns.values()
                ]
        else:
            result["hint"] = "Call analyze(path=...) to load a binary."
        return mcpstate.json_reply(result)

    # ── analyze ─────────────────────────────────────────────────────────
    if name == "analyze":
        path = arguments["path"]
        mapping_file = arguments.get("mapping_file")
        engine.config.mapping_file = Path(mapping_file) if mapping_file else None
        model = await engine.analyze(path)
        mcpstate.current_model = model
        mcpstate.analysis_config = {
            "path": str(Path(path).resolve()),
            "backends_used": [a.name() for a in engine.registry.all_available()],
        }
        return mcpstate.json_reply({
            "status": "ok",
            "platform": model.binary.platform.value,
            "format": model.binary.format.value,
            "framework": model.binary.framework.value,
            "sha256": model.binary.sha256[:16],
            "size_bytes": model.binary.size_bytes,
            "functions": len(model.functions),
            "strings": len(model.get_strings()),
            "hint": "Next: detect_protections, get_functions, list_source_files, detect_protocols",
        })

    # ── get_functions ───────────────────────────────────────────────────
    if name == "get_functions":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        funcs = mcpstate.current_model.functions
        search = arguments.get("search")
        classification = arguments.get("classification")
        layer = arguments.get("layer")
        if search:
            sl = search.lower()
            funcs = [f for f in funcs if sl in f.name.lower()]
        if classification:
            funcs = [f for f in funcs if f.classification == classification]
        if layer:
            funcs = [f for f in funcs if f.layer == layer]
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 50)
        page = funcs[offset:offset + limit]
        return mcpstate.json_reply({
            "total": len(funcs), "offset": offset, "limit": limit,
            "has_more": offset + limit < len(funcs),
            "functions": [
                {"address": f.address, "name": f.name, "classification": f.classification,
                 "layer": f.layer, "language": f.language,
                 "has_decompiled": f.decompiled is not None}
                for f in page
            ],
        })

    # ── get_function ────────────────────────────────────────────────────
    if name == "get_function":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        func = mcpstate.current_model.get_function(arguments["address"])
        if not func:
            # Stripped binary: no symbol at this address (e.g. an .init_array
            # constructor). Disassemble it raw so it is still reachable.
            reply = await mcpstate.raw_disasm_reply(
                arguments["address"], {"layer": "native"})
            return reply or mcpstate.error(
                f"Function {arguments['address']} not found.")
        callees = mcpstate.current_model.get_callees(func.address)
        callers = mcpstate.current_model.get_callers(func.address)
        return mcpstate.json_reply({
            "address": func.address, "name": func.name, "language": func.language,
            "classification": func.classification, "layer": func.layer,
            "source_backend": func.source_backend,
            "decompiled": func.decompiled,
            "signature": func.signature,
            "callees": [{"address": c.address, "name": c.name} for c in callees],
            "callers": [{"address": c.address, "name": c.name} for c in callers],
        })

    # ── get_strings ─────────────────────────────────────────────────────
    if name == "get_strings":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 100)
        all_strings = mcpstate.current_model.get_strings(pattern=pattern)
        return mcpstate.json_reply({
            "total": len(all_strings),
            "strings": [{"address": s.address, "value": s.value, "section": s.section}
                        for s in all_strings[:limit]],
        })

    # ── get_callgraph ───────────────────────────────────────────────────
    if name == "get_callgraph":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        address = arguments["address"]
        depth = min(arguments.get("depth", 2), 10)
        nodes, edges = [], []
        visited = set()
        def walk(addr, d):
            if addr in visited or d > depth:
                return
            visited.add(addr)
            func = mcpstate.current_model.get_function(addr)
            if not func:
                return
            nodes.append({"address": addr, "name": func.name, "classification": func.classification})
            for c in mcpstate.current_model.get_callees(addr):
                edges.append({"from": addr, "to": c.address, "type": "calls"})
                walk(c.address, d + 1)
            for c in mcpstate.current_model.get_callers(addr):
                edges.append({"from": c.address, "to": addr, "type": "called_by"})
                if d < 1:
                    walk(c.address, d + 1)
        walk(address, 0)
        return mcpstate.json_reply({"nodes": nodes, "edges": edges, "center": address})

    # ── get_manifest ────────────────────────────────────────────────────
    if name == "get_manifest":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        if mcpstate.current_model.binary.platform.value != "android":
            return mcpstate.error("get_manifest is only available for Android binaries.")
        # Try jadx decoded manifest first
        config = engine.config
        sha = mcpstate.current_model.binary.sha256[:12]
        jadx_manifest = config.project_dir / "jadx" / sha / "resources" / "AndroidManifest.xml"
        if jadx_manifest.exists():
            return mcpstate.json_reply({"source": "jadx", "xml": jadx_manifest.read_text(errors="replace")})
        raw_manifest = config.project_dir / "unpacked" / sha / "AndroidManifest.xml"
        if raw_manifest.exists():
            content = raw_manifest.read_text(errors="replace")
            if content.lstrip().startswith("<?xml") or content.lstrip().startswith("<manifest"):
                return mcpstate.json_reply({"source": "raw", "xml": content})
            return mcpstate.error("Manifest is binary-encoded. Install jadx to decode it.")
        return mcpstate.error("AndroidManifest.xml not found in unpacked directory.")

    # ── get_manifest_findings ───────────────────────────────────────────
    if name == "get_manifest_findings":
        if mcpstate.current_model is None:
            return mcpstate.json_reply({"error": "no project loaded; call analyze(path=...) first"})
        from chimera.parsers.android_manifest import parse_manifest as _pm
        from chimera.parsers.network_security_config import parse_nsc as _pn
        from chimera.detection_engineering.manifest_findings import (
            build_findings_from_models,
        )
        import tempfile
        from pathlib import Path as _P

        cache = engine.cache
        sha = mcpstate.current_model.binary.sha256
        mxml = cache.get(sha, "manifest_xml")
        if mxml is None:
            return mcpstate.json_reply({"findings": [], "hint": "no manifest_xml in cache (non-Android binary?)"})
        with tempfile.TemporaryDirectory() as td:
            mp = _P(td) / "AndroidManifest.xml"
            mp.write_bytes(mxml)
            manifest_model = _pm(mp)
            nsc_model = None
            nxml = cache.get(sha, "nsc_xml")
            if nxml:
                np = _P(td) / "network_security_config.xml"
                np.write_bytes(nxml)
                nsc_model = _pn(np)
            findings = build_findings_from_models(manifest_model, nsc=nsc_model)
        return mcpstate.json_reply({"findings": [f.to_dict() for f in findings]})

    # ── diff_projects ───────────────────────────────────────────────────
    if name == "diff_projects":
        from chimera.diff import (
            ProjectNotInCacheError, diff_projects as _diff,
            load_project, render_json,
        )
        a_spec = arguments["a"]
        b_spec = arguments["b"]
        try:
            snap_a = load_project(a_spec, engine.cache)
            snap_b = load_project(b_spec, engine.cache)
        except ProjectNotInCacheError as e:
            return mcpstate.json_reply({"error": f"project not in cache: {e}"})
        except ValueError as e:
            return mcpstate.json_reply({"error": str(e)})
        return mcpstate.json_reply(render_json(_diff(snap_a, snap_b)))

    # ── get_info ────────────────────────────────────────────────────────
    if name == "get_info":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded. Call analyze first.")
        b = mcpstate.current_model.binary
        return mcpstate.json_reply({
            "path": str(b.path), "sha256": b.sha256,
            "platform": b.platform.value, "format": b.format.value,
            "arch": b.arch.value, "framework": b.framework.value,
            "size_bytes": b.size_bytes, "package_name": b.package_name,
            "functions": len(mcpstate.current_model.functions),
            "strings": len(mcpstate.current_model.get_strings()),
        })

    # ── detect_protections ──────────────────────────────────────────────
    if name == "detect_protections":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded. Call analyze first.")
        from chimera.bypass.detector import ProtectionDetector
        from chimera.cli.protection import merge_native_profile
        strings = [s.value for s in mcpstate.current_model.get_strings()]
        profile = ProtectionDetector().detect_from_strings(strings, mcpstate.current_model.binary.platform.value)
        # The mobile string detector never sees a PE/ELF import table, so on a
        # native (incl. .NET) target it misses anti-debug imports like
        # CheckRemoteDebuggerPresent. Fold in the PE/ELF pipeline's cached
        # native_detector profile, exactly as the `protection` CLI does.
        native = engine.cache.get_json(
            mcpstate.current_model.binary.sha256, "native_protection") or {}
        merge_native_profile(profile, native)
        return mcpstate.json_reply({
            "root_detection": profile.has_root_detection,
            "jailbreak_detection": profile.has_jailbreak_detection,
            "anti_frida": profile.has_anti_frida,
            "anti_debug": profile.has_anti_debug,
            "ssl_pinning": profile.has_ssl_pinning,
            "integrity": profile.has_integrity_check,
            "packer": profile.has_packer, "packer_name": profile.packer_name,
            # ELF exploit-mitigation posture (RELRO/NX/PIE, stack canary,
            # FORTIFY, and ARM MTE/PAC/BTI + seccomp). Empty on non-ELF.
            "hardening": native.get("hardening") or {},
            "has_any_protection": profile.has_any_protection,
            "bypass_order": profile.bypass_order(),
            "details": profile.details[:20],
        })

    # ── detect_sdks ─────────────────────────────────────────────────────
    if name == "detect_sdks":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        from chimera.sdk.analyzer import SDKAnalyzer
        packages = set()
        for func in mcpstate.current_model.functions:
            if "." in func.name:
                packages.add(func.name.rsplit(".", 1)[0])
        analyzer = SDKAnalyzer()
        detected = analyzer.detect_from_packages(list(packages))
        return mcpstate.json_reply(analyzer.summarize(detected))

    # ── detect_framework ────────────────────────────────────────────────
    if name == "detect_framework":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        return mcpstate.json_reply({"framework": mcpstate.current_model.binary.framework.value})

    # ── detect_protocols ────────────────────────────────────────────────
    if name == "detect_protocols":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        from chimera.protocol.analyzer import ProtocolAnalyzer
        strings = [s.value for s in mcpstate.current_model.get_strings()]
        analyzer = ProtocolAnalyzer()
        protocols = analyzer.detect_protocols(strings)
        endpoints = analyzer.extract_endpoints(strings)
        return mcpstate.json_reply({
            **protocols,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:50],
        })

    # ── get_bypass_scripts ──────────────────────────────────────────────
    if name == "get_bypass_scripts":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded. Call analyze first.")
        from chimera.bypass.detector import ProtectionDetector
        from chimera.bypass.orchestrator import BypassOrchestrator
        strings = [s.value for s in mcpstate.current_model.get_strings()]
        platform = mcpstate.current_model.binary.platform.value
        profile = ProtectionDetector().detect_from_strings(strings, platform)
        if not profile.has_any_protection:
            return mcpstate.json_reply({"has_protections": False, "message": "No protections detected."})
        orchestrator = BypassOrchestrator()
        chain = orchestrator.build_bypass_chain(profile, platform)
        combined = orchestrator.get_combined_script(profile, platform)
        return mcpstate.json_reply({
            "has_protections": True,
            "bypass_order": profile.bypass_order(),
            "scripts": [{"name": s["name"], "type": s["type"]} for s in chain],
            "combined_script": combined,
        })

    # ── get_dynamic_hooks ───────────────────────────────────────────────
    if name == "get_dynamic_hooks":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        from chimera.dynamic.code_capture import DynamicCodeCapture
        platform = mcpstate.current_model.binary.platform.value
        capture = DynamicCodeCapture()
        script = capture.get_capture_script(platform)
        return mcpstate.json_reply({
            "platform": platform,
            "description": f"Frida script to intercept runtime code loading on {platform}. "
                           "Hooks DexClassLoader, InMemoryDexClassLoader, System.load/loadLibrary (Android) "
                           "or dlopen, NSBundle.load (iOS).",
            "script": script,
        })

    # ── pull_app ────────────────────────────────────────────────────────
    return None
