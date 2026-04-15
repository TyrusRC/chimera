"""Chimera MCP Server — exposes RE capabilities as tools for LLMs."""
from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine

logger = logging.getLogger(__name__)
server = Server("chimera")
_engine: ChimeraEngine | None = None
_current_model = None
_analysis_config: dict = {}  # tracks what backends ran, paths, etc.


def _get_engine() -> ChimeraEngine:
    global _engine
    if _engine is None:
        _engine = ChimeraEngine(ChimeraConfig())
    return _engine


def _json(data) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2))]


def _error(msg: str) -> list[TextContent]:
    return _json({"error": msg})


def _require_model() -> bool:
    return _current_model is not None


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # --- Session ---
        Tool(name="status",
             description="Show current session state: whether a binary is loaded, what backends are available, analysis stats. Call this first to understand what you can do.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="analyze",
             description="Run full static analysis on a mobile binary (APK/IPA). This is the entry point — must be called before query tools.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Absolute path to APK or IPA file"},
             }, "required": ["path"]}),

        # --- Query: Findings ---
        Tool(name="get_findings",
             description="Get vulnerability findings. Filter by severity or rule_id. Supports pagination via offset.",
             inputSchema={"type": "object", "properties": {
                 "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                 "rule_id": {"type": "string"},
                 "offset": {"type": "integer", "default": 0, "description": "Skip first N findings"},
                 "limit": {"type": "integer", "default": 30},
             }}),
        Tool(name="search_finding_evidence",
             description="Search across all finding titles, descriptions, evidence, and locations for a text pattern.",
             inputSchema={"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "Text to search for (case-insensitive)"},
             }, "required": ["pattern"]}),
        Tool(name="update_finding",
             description="Mark a finding as false_positive or confirmed. Use the finding index from get_findings results.",
             inputSchema={"type": "object", "properties": {
                 "index": {"type": "integer", "description": "Finding index in the findings list"},
                 "status": {"type": "string", "enum": ["confirmed", "false_positive"]},
                 "reason": {"type": "string", "description": "Why this status was set"},
             }, "required": ["index", "status"]}),

        # --- Query: Code ---
        Tool(name="get_functions",
             description="List functions. Search by name, filter by classification/layer. Returns address, name, whether decompiled code exists.",
             inputSchema={"type": "object", "properties": {
                 "search": {"type": "string"}, "classification": {"type": "string"},
                 "layer": {"type": "string", "enum": ["native", "java", "objc", "dart", "js"]},
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 50},
             }}),
        Tool(name="get_function",
             description="Get full detail for one function: decompiled source, callers, callees.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
             }, "required": ["address"]}),
        Tool(name="get_strings",
             description="Search strings extracted from the binary. Supports regex patterns.",
             inputSchema={"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "Regex pattern to filter strings"},
                 "limit": {"type": "integer", "default": 100},
             }}),
        Tool(name="get_callgraph",
             description="Get call graph around a function (callers + callees) up to specified depth.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string"}, "depth": {"type": "integer", "default": 2},
             }, "required": ["address"]}),
        Tool(name="get_manifest",
             description="Get the decoded AndroidManifest.xml content (Android only). Useful for reviewing permissions, components, intent-filters.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Detection ---
        Tool(name="get_info",
             description="Get binary metadata: platform, framework, format, SHA256, size, package name.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_protections",
             description="Detect active security protections: root/jailbreak detection, anti-Frida, anti-debug, SSL pinning, integrity checks.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_sdks",
             description="Fingerprint third-party SDKs from function package names.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_framework",
             description="Get detected cross-platform framework (Flutter, React Native, Xamarin, Unity, Cordova, or native).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_protocols",
             description="Detect API protocols (REST, gRPC, GraphQL, WebSocket, Protobuf) and extract endpoints from strings.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Actions ---
        Tool(name="get_bypass_scripts",
             description="Get Frida bypass scripts for detected protections. Returns a combined JS script ready to load via Frida.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_dynamic_hooks",
             description="Get Frida hook script for capturing runtime-loaded code (DexClassLoader, dlopen, System.loadLibrary).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="pull_app",
             description="Pull an installed app from a connected device. Returns path to the downloaded APK/IPA.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID from list_devices"},
                 "package": {"type": "string", "description": "Package name (e.g. com.example.app)"},
             }, "required": ["device_id", "package"]}),
        Tool(name="run_semgrep",
             description="Run Semgrep SAST rules on decompiled sources. Requires semgrep installed and a prior analyze call with jadx.",
             inputSchema={"type": "object", "properties": {
                 "rules": {"type": "string", "default": "auto", "description": "Semgrep rule config (auto, p/java, path to rules)"},
             }}),

        # --- Export & Devices ---
        Tool(name="export_report",
             description="Export findings as SARIF, JSON, or Markdown report.",
             inputSchema={"type": "object", "properties": {
                 "format": {"type": "string", "enum": ["sarif", "json", "markdown"], "default": "sarif"},
             }}),
        Tool(name="list_devices",
             description="List connected Android (ADB) and iOS (libimobiledevice) devices.",
             inputSchema={"type": "object", "properties": {}}),
    ]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    global _current_model, _analysis_config
    engine = _get_engine()

    # ── status ──────────────────────────────────────────────────────────
    if name == "status":
        available = [a.name() for a in engine.registry.all_available()]
        unavailable = [a.name() for a in engine.registry.all_registered() if not a.is_available()]
        result = {
            "loaded": _current_model is not None,
            "backends_available": available,
            "backends_missing": unavailable,
        }
        if _current_model:
            b = _current_model.binary
            findings = getattr(_current_model, "findings", [])
            result.update({
                "binary": b.path.name,
                "platform": b.platform.value,
                "framework": b.framework.value,
                "functions": len(_current_model.functions),
                "strings": len(_current_model.get_strings()),
                "findings": len(findings),
                "analysis_config": _analysis_config,
            })
        else:
            result["hint"] = "Call analyze(path=...) to load a binary."
        return _json(result)

    # ── analyze ─────────────────────────────────────────────────────────
    elif name == "analyze":
        path = arguments["path"]
        model = await engine.analyze(path)
        _current_model = model
        findings = getattr(model, "findings", [])
        _analysis_config = {
            "path": str(Path(path).resolve()),
            "backends_used": [a.name() for a in engine.registry.all_available()],
        }
        return _json({
            "status": "ok",
            "platform": model.binary.platform.value,
            "format": model.binary.format.value,
            "framework": model.binary.framework.value,
            "sha256": model.binary.sha256[:16],
            "size_bytes": model.binary.size_bytes,
            "functions": len(model.functions),
            "strings": len(model.get_strings()),
            "findings": len(findings),
            "findings_summary": {
                sev: sum(1 for f in findings if f.severity.value == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "hint": "Next: get_findings, detect_protections, get_functions, detect_protocols",
        })

    # ── get_findings ────────────────────────────────────────────────────
    elif name == "get_findings":
        if not _require_model():
            return _error("No analysis loaded. Call analyze first.")
        findings = getattr(_current_model, "findings", [])
        severity = arguments.get("severity")
        rule_id = arguments.get("rule_id")
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        if rule_id:
            findings = [f for f in findings if f.rule_id == rule_id]
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 30)
        page = findings[offset:offset + limit]
        return _json({
            "total": len(findings),
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < len(findings),
            "findings": [f.to_dict() for f in page],
        })

    # ── search_finding_evidence ─────────────────────────────────────────
    elif name == "search_finding_evidence":
        if not _require_model():
            return _error("No analysis loaded.")
        pattern = arguments["pattern"].lower()
        findings = getattr(_current_model, "findings", [])
        matched = []
        for f in findings:
            searchable = " ".join(filter(None, [
                f.title, f.description, f.evidence_static,
                f.evidence_dynamic, f.rule_id, f.location,
            ])).lower()
            if pattern in searchable:
                matched.append(f.to_dict())
        return _json({"pattern": arguments["pattern"], "matches": len(matched), "findings": matched[:30]})

    # ── update_finding ──────────────────────────────────────────────────
    elif name == "update_finding":
        if not _require_model():
            return _error("No analysis loaded.")
        findings = getattr(_current_model, "findings", [])
        idx = arguments["index"]
        if idx < 0 or idx >= len(findings):
            return _error(f"Index {idx} out of range (0-{len(findings)-1}).")
        finding = findings[idx]
        status = arguments["status"]
        reason = arguments.get("reason", "")
        if status == "false_positive":
            finding.mark_false_positive(reason)
        elif status == "confirmed":
            finding.confirm(reason)
        return _json({"updated": True, "index": idx, "new_status": finding.status.value,
                       "rule_id": finding.rule_id, "title": finding.title})

    # ── get_functions ───────────────────────────────────────────────────
    elif name == "get_functions":
        if not _require_model():
            return _error("No analysis loaded.")
        funcs = _current_model.functions
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
        return _json({
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
    elif name == "get_function":
        if not _require_model():
            return _error("No analysis loaded.")
        func = _current_model.get_function(arguments["address"])
        if not func:
            return _error(f"Function {arguments['address']} not found.")
        callees = _current_model.get_callees(func.address)
        callers = _current_model.get_callers(func.address)
        return _json({
            "address": func.address, "name": func.name, "language": func.language,
            "classification": func.classification, "layer": func.layer,
            "source_backend": func.source_backend,
            "decompiled": func.decompiled,
            "signature": func.signature,
            "callees": [{"address": c.address, "name": c.name} for c in callees],
            "callers": [{"address": c.address, "name": c.name} for c in callers],
        })

    # ── get_strings ─────────────────────────────────────────────────────
    elif name == "get_strings":
        if not _require_model():
            return _error("No analysis loaded.")
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 100)
        all_strings = _current_model.get_strings(pattern=pattern)
        return _json({
            "total": len(all_strings),
            "strings": [{"address": s.address, "value": s.value, "section": s.section}
                        for s in all_strings[:limit]],
        })

    # ── get_callgraph ───────────────────────────────────────────────────
    elif name == "get_callgraph":
        if not _require_model():
            return _error("No analysis loaded.")
        address = arguments["address"]
        depth = min(arguments.get("depth", 2), 10)
        nodes, edges = [], []
        visited = set()
        def walk(addr, d):
            if addr in visited or d > depth:
                return
            visited.add(addr)
            func = _current_model.get_function(addr)
            if not func:
                return
            nodes.append({"address": addr, "name": func.name, "classification": func.classification})
            for c in _current_model.get_callees(addr):
                edges.append({"from": addr, "to": c.address, "type": "calls"})
                walk(c.address, d + 1)
            for c in _current_model.get_callers(addr):
                edges.append({"from": c.address, "to": addr, "type": "called_by"})
                if d < 1:
                    walk(c.address, d + 1)
        walk(address, 0)
        return _json({"nodes": nodes, "edges": edges, "center": address})

    # ── get_manifest ────────────────────────────────────────────────────
    elif name == "get_manifest":
        if not _require_model():
            return _error("No analysis loaded.")
        if _current_model.binary.platform.value != "android":
            return _error("get_manifest is only available for Android binaries.")
        # Try jadx decoded manifest first
        config = engine.config
        sha = _current_model.binary.sha256[:12]
        jadx_manifest = config.project_dir / "jadx" / sha / "resources" / "AndroidManifest.xml"
        if jadx_manifest.exists():
            return _json({"source": "jadx", "xml": jadx_manifest.read_text(errors="replace")})
        raw_manifest = config.project_dir / "unpacked" / sha / "AndroidManifest.xml"
        if raw_manifest.exists():
            content = raw_manifest.read_text(errors="replace")
            if content.lstrip().startswith("<?xml") or content.lstrip().startswith("<manifest"):
                return _json({"source": "raw", "xml": content})
            return _error("Manifest is binary-encoded. Install jadx to decode it.")
        return _error("AndroidManifest.xml not found in unpacked directory.")

    # ── get_info ────────────────────────────────────────────────────────
    elif name == "get_info":
        if not _require_model():
            return _error("No analysis loaded. Call analyze first.")
        b = _current_model.binary
        return _json({
            "path": str(b.path), "sha256": b.sha256,
            "platform": b.platform.value, "format": b.format.value,
            "arch": b.arch.value, "framework": b.framework.value,
            "size_bytes": b.size_bytes, "package_name": b.package_name,
            "functions": len(_current_model.functions),
            "strings": len(_current_model.get_strings()),
            "findings": len(getattr(_current_model, "findings", [])),
        })

    # ── detect_protections ──────────────────────────────────────────────
    elif name == "detect_protections":
        if not _require_model():
            return _error("No analysis loaded. Call analyze first.")
        from chimera.bypass.detector import ProtectionDetector
        strings = [s.value for s in _current_model.get_strings()]
        profile = ProtectionDetector().detect_from_strings(strings, _current_model.binary.platform.value)
        return _json({
            "root_detection": profile.has_root_detection,
            "jailbreak_detection": profile.has_jailbreak_detection,
            "anti_frida": profile.has_anti_frida,
            "anti_debug": profile.has_anti_debug,
            "ssl_pinning": profile.has_ssl_pinning,
            "integrity": profile.has_integrity_check,
            "packer": profile.has_packer, "packer_name": profile.packer_name,
            "has_any_protection": profile.has_any_protection,
            "bypass_order": profile.bypass_order(),
            "details": profile.details[:20],
        })

    # ── detect_sdks ─────────────────────────────────────────────────────
    elif name == "detect_sdks":
        if not _require_model():
            return _error("No analysis loaded.")
        from chimera.sdk.analyzer import SDKAnalyzer
        packages = set()
        for func in _current_model.functions:
            if "." in func.name:
                packages.add(func.name.rsplit(".", 1)[0])
        analyzer = SDKAnalyzer()
        detected = analyzer.detect_from_packages(list(packages))
        return _json(analyzer.summarize(detected))

    # ── detect_framework ────────────────────────────────────────────────
    elif name == "detect_framework":
        if not _require_model():
            return _error("No analysis loaded.")
        return _json({"framework": _current_model.binary.framework.value})

    # ── detect_protocols ────────────────────────────────────────────────
    elif name == "detect_protocols":
        if not _require_model():
            return _error("No analysis loaded.")
        from chimera.protocol.analyzer import ProtocolAnalyzer
        strings = [s.value for s in _current_model.get_strings()]
        analyzer = ProtocolAnalyzer()
        protocols = analyzer.detect_protocols(strings)
        endpoints = analyzer.extract_endpoints(strings)
        return _json({
            **protocols,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:50],
        })

    # ── get_bypass_scripts ──────────────────────────────────────────────
    elif name == "get_bypass_scripts":
        if not _require_model():
            return _error("No analysis loaded. Call analyze first.")
        from chimera.bypass.detector import ProtectionDetector
        from chimera.bypass.orchestrator import BypassOrchestrator
        strings = [s.value for s in _current_model.get_strings()]
        platform = _current_model.binary.platform.value
        profile = ProtectionDetector().detect_from_strings(strings, platform)
        if not profile.has_any_protection:
            return _json({"has_protections": False, "message": "No protections detected."})
        orchestrator = BypassOrchestrator()
        chain = orchestrator.build_bypass_chain(profile, platform)
        combined = orchestrator.get_combined_script(profile, platform)
        return _json({
            "has_protections": True,
            "bypass_order": profile.bypass_order(),
            "scripts": [{"name": s["name"], "type": s["type"]} for s in chain],
            "combined_script": combined,
        })

    # ── get_dynamic_hooks ───────────────────────────────────────────────
    elif name == "get_dynamic_hooks":
        if not _require_model():
            return _error("No analysis loaded.")
        from chimera.dynamic.code_capture import DynamicCodeCapture
        platform = _current_model.binary.platform.value
        capture = DynamicCodeCapture()
        script = capture.get_capture_script(platform)
        return _json({
            "platform": platform,
            "description": f"Frida script to intercept runtime code loading on {platform}. "
                           "Hooks DexClassLoader, InMemoryDexClassLoader, System.load/loadLibrary (Android) "
                           "or dlopen, NSBundle.load (iOS).",
            "script": script,
        })

    # ── pull_app ────────────────────────────────────────────────────────
    elif name == "pull_app":
        device_id = arguments["device_id"]
        package = arguments["package"]
        output_dir = str(engine.config.project_dir / "pulled")
        # Detect platform by trying Android first, then iOS
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    pulled_path = await mgr.pull_app(device_id, package, output_dir)
                    if pulled_path:
                        await mgr.cleanup()
                        return _json({"status": "ok", "path": pulled_path, "package": package,
                                       "device_id": device_id,
                                       "hint": f"Call analyze(path=\"{pulled_path}\") to start analysis."})
                except (OSError, RuntimeError):
                    pass
                await mgr.cleanup()
        return _error(f"Failed to pull {package} from device {device_id}. Check device connection and package name.")

    # ── run_semgrep ─────────────────────────────────────────────────────
    elif name == "run_semgrep":
        if not _require_model():
            return _error("No analysis loaded.")
        semgrep = engine.registry.get("semgrep")
        if not semgrep or not semgrep.is_available():
            return _error("Semgrep is not installed. Install via: pip install semgrep")
        sha = _current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        if not sources_dir.exists():
            return _error("No decompiled sources found. Semgrep requires jadx output.")
        rules = arguments.get("rules", "auto")
        result = await semgrep.analyze(str(sources_dir), {"rules": rules})
        findings_count = len(result.get("results", []))
        return _json({
            "return_code": result.get("return_code"),
            "findings": findings_count,
            "results": result.get("results", [])[:30],
            "errors": result.get("errors", [])[:10],
        })

    # ── export_report ───────────────────────────────────────────────────
    elif name == "export_report":
        if not _require_model():
            return _error("No analysis loaded.")
        findings = getattr(_current_model, "findings", [])
        binary_info = {
            "name": _current_model.binary.path.name,
            "sha256": _current_model.binary.sha256,
            "platform": _current_model.binary.platform.value,
            "format": _current_model.binary.format.value,
        }
        fmt = arguments.get("format", "sarif")
        if fmt == "sarif":
            from chimera.report.sarif import generate_sarif
            return [TextContent(type="text", text=generate_sarif(findings))]
        elif fmt == "json":
            from chimera.report.json_report import generate_json
            return [TextContent(type="text", text=generate_json(findings, binary_info))]
        else:
            from chimera.report.markdown import generate_markdown
            return [TextContent(type="text", text=generate_markdown(findings, binary_info))]

    # ── list_devices ────────────────────────────────────────────────────
    elif name == "list_devices":
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        devices = []
        for mgr in [AndroidDeviceManager(), IOSDeviceManager()]:
            if mgr.is_available:
                try:
                    for d in await mgr.list_devices():
                        devices.append({"id": d.id, "platform": d.platform.value,
                                        "model": d.model, "os": d.os_version,
                                        "rooted": d.is_rooted, "jailbroken": d.is_jailbroken})
                except (OSError, RuntimeError) as e:
                    logger.warning("Device listing failed: %s", e)
                await mgr.cleanup()
        if not devices:
            return _json({"devices": [], "hint": "No devices found. Connect via USB and ensure adb/libimobiledevice is installed."})
        return _json({"devices": devices})

    return _error(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
