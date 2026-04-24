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


_ALLOWED_CACHE_CATEGORIES = frozenset({
    "triage",
    "jadx",
    "manifest_xml",
    "info_plist",
    "class_dump",
})
_ALLOWED_CACHE_PREFIXES = ("r2_", "ghidra_")


def _is_allowed_category(category: str) -> bool:
    """Whitelist-check a cache category. Rejects path traversal and unknown keys."""
    if not isinstance(category, str) or not category:
        return False
    # Rejection rule: any path-like characters
    if any(c in category for c in ("/", "\\", "..")):
        return False
    if category in _ALLOWED_CACHE_CATEGORIES:
        return True
    return any(category.startswith(prefix) for prefix in _ALLOWED_CACHE_PREFIXES)


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
                 "mapping_file": {
                     "type": "string",
                     "description": "Optional ProGuard/R8 mapping.txt path to restore original identifiers",
                 },
             }, "required": ["path"]}),

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

        # --- Devices ---
        Tool(name="list_devices",
             description="List connected Android (ADB) and iOS (libimobiledevice) devices.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Source & Artifact Browsing ---
        Tool(name="list_source_files",
             description="List decompiled source files from jadx output. Browse by package path. Essential for reading Java/Kotlin source after analysis.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "default": "", "description": "Relative path within jadx sources (e.g. 'com/example/app'). Empty for root."},
                 "pattern": {"type": "string", "description": "Glob pattern to filter files (e.g. '*.java', '**/*Activity*')"},
             }}),
        Tool(name="read_source",
             description="Read a decompiled source file from jadx output. Use list_source_files to find paths first.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Relative path within jadx sources (e.g. 'com/example/app/MainActivity.java')"},
                 "offset": {"type": "integer", "default": 0, "description": "Line offset to start reading from"},
                 "limit": {"type": "integer", "default": 200, "description": "Max lines to return"},
             }, "required": ["path"]}),
        Tool(name="read_cache",
             description="Read a cached analysis artifact (r2 triage, Ghidra output, jadx summary). Use list_artifacts to find keys.",
             inputSchema={"type": "object", "properties": {
                 "category": {"type": "string", "description": "Cache key (e.g. 'triage', 'r2_libnative.so', 'ghidra_libnative.so', 'jadx')"},
             }, "required": ["category"]}),
        Tool(name="list_artifacts",
             description="List all cached analysis artifacts and on-disk outputs for the current binary.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_disassembly",
             description="Get disassembly instructions for a function by address.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
             }, "required": ["address"]}),
        Tool(name="get_class_headers",
             description="Read ObjC class-dump headers from iOS analysis. Lists header files or reads a specific header.",
             inputSchema={"type": "object", "properties": {
                 "file": {"type": "string", "description": "Header filename to read (e.g. 'AppDelegate.h'). Omit to list all headers."},
             }}),
        # --- Device Interaction ---
        Tool(name="list_packages",
             description="List installed packages/apps on a connected device.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID from list_devices"},
             }, "required": ["device_id"]}),
        Tool(name="get_logcat",
             description="Get Android logcat output filtered by package. Useful for observing runtime behavior.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID"},
                 "package": {"type": "string", "description": "Package name to filter logs for"},
                 "lines": {"type": "integer", "default": 100, "description": "Number of log lines"},
             }, "required": ["device_id", "package"]}),
        Tool(name="setup_proxy",
             description="Configure HTTP proxy on an Android device for traffic interception (e.g. Burp Suite).",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"},
             }, "required": ["device_id", "host", "port"]}),
        Tool(name="clear_proxy",
             description="Remove HTTP proxy configuration from an Android device.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string"},
             }, "required": ["device_id"]}),

        # --- Frida Dynamic Analysis ---
        Tool(name="start_frida_server",
             description="Start frida-server on a connected device (requires root/jailbreak). Must be called before frida_attach/frida_spawn.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID"},
             }, "required": ["device_id"]}),
        Tool(name="frida_spawn",
             description="Spawn an app with Frida instrumentation. Optionally inject a script (e.g. bypass script from get_bypass_scripts).",
             inputSchema={"type": "object", "properties": {
                 "package": {"type": "string", "description": "Package name to spawn"},
                 "device_id": {"type": "string", "description": "Device ID (optional, uses USB device if omitted)"},
                 "script": {"type": "string", "description": "JavaScript source to inject at spawn"},
             }, "required": ["package"]}),
        Tool(name="frida_attach",
             description="Attach Frida to a running app process for live instrumentation.",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Package name or PID to attach to"},
                 "device_id": {"type": "string", "description": "Device ID (optional)"},
             }, "required": ["target"]}),
        Tool(name="frida_exec",
             description="Execute JavaScript code in an active Frida session. Use to call RPC exports or run ad-hoc hooks.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key (package name or PID used in attach/spawn)"},
                 "code": {"type": "string", "description": "JavaScript code to evaluate"},
             }, "required": ["session_key", "code"]}),
        Tool(name="frida_load_script",
             description="Load a Frida script into an active session. Use with bypass scripts or custom hooks.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key from frida_attach/frida_spawn"},
                 "script": {"type": "string", "description": "JavaScript source code to load"},
             }, "required": ["session_key", "script"]}),
        Tool(name="frida_messages",
             description="Get all Frida messages from an active session. Shows hook output, code capture events, errors.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key"},
                 "since": {"type": "integer", "default": 0, "description": "Return messages after this index"},
             }, "required": ["session_key"]}),
        Tool(name="frida_detach",
             description="Detach from a Frida session and clean up.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key to detach"},
             }, "required": ["session_key"]}),

        # --- Fuzzing ---
        Tool(name="start_fuzz",
             description="Start an AFL++ fuzzing campaign on a native library. Requires afl-fuzz installed.",
             inputSchema={"type": "object", "properties": {
                 "binary": {"type": "string", "description": "Path to native binary/library to fuzz"},
                 "input_dir": {"type": "string", "description": "Directory with seed inputs"},
                 "output_dir": {"type": "string", "description": "Directory for fuzzing output"},
                 "duration": {"type": "integer", "default": 300, "description": "Fuzzing duration in seconds"},
                 "qemu": {"type": "boolean", "default": True, "description": "Use QEMU mode for ARM binaries"},
             }, "required": ["binary", "input_dir", "output_dir"]}),
        Tool(name="fuzz_status",
             description="Check status and results of a running or completed fuzzing campaign.",
             inputSchema={"type": "object", "properties": {
                 "campaign_id": {"type": "string", "description": "Campaign ID from start_fuzz result"},
             }, "required": ["campaign_id"]}),

        # --- Configuration ---
        Tool(name="get_config",
             description="Get or modify Chimera analysis configuration. Call with no params to read current config.",
             inputSchema={"type": "object", "properties": {
                 "set": {"type": "object", "description": "Key-value pairs to update (e.g. {\"skip_dynamic\": false, \"ghidra_max_mem\": \"8g\"})"},
             }}),
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
            result.update({
                "binary": b.path.name,
                "platform": b.platform.value,
                "framework": b.framework.value,
                "sha256": b.sha256[:16],
                "functions": len(_current_model.functions),
                "strings": len(_current_model.get_strings()),
                "analysis_config": _analysis_config,
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
        return _json(result)

    # ── analyze ─────────────────────────────────────────────────────────
    elif name == "analyze":
        path = arguments["path"]
        mapping_file = arguments.get("mapping_file")
        engine.config.mapping_file = Path(mapping_file) if mapping_file else None
        model = await engine.analyze(path)
        _current_model = model
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
            "hint": "Next: detect_protections, get_functions, list_source_files, detect_protocols",
        })

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
                    pulled_paths = await mgr.pull_app(device_id, package, output_dir)
                    if pulled_paths:
                        await mgr.cleanup()
                        primary = pulled_paths[0]
                        extra = pulled_paths[1:]
                        response = {
                            "status": "ok",
                            "path": primary,
                            "split_paths": pulled_paths,
                            "package": package,
                            "device_id": device_id,
                            "hint": f"Call analyze(path=\"{primary}\") to start analysis.",
                        }
                        if extra:
                            response["note"] = (
                                f"{len(extra)} additional split APK(s) pulled alongside base; "
                                "pass the base to analyze()."
                            )
                        return _json(response)
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

    # ── list_source_files ──────────────────────────────────────────────
    elif name == "list_source_files":
        if not _require_model():
            return _error("No analysis loaded.")
        sha = _current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        if not sources_dir.exists():
            return _error("No decompiled sources. jadx must be installed and analysis must have run.")
        rel_path = arguments.get("path", "")
        target = sources_dir / rel_path if rel_path else sources_dir
        try:
            target.resolve().relative_to(sources_dir.resolve())
        except ValueError:
            return _error("Path traversal not allowed.")
        if not target.exists():
            return _error(f"Path not found: {rel_path}")
        pattern = arguments.get("pattern")
        if pattern:
            files = sorted(target.rglob(pattern))
        elif target.is_dir():
            files = sorted(target.iterdir())
        else:
            files = [target]
        entries = []
        for f in files[:200]:
            rel = f.relative_to(sources_dir)
            entries.append({"path": str(rel), "type": "dir" if f.is_dir() else "file",
                            "size": f.stat().st_size if f.is_file() else None})
        return _json({"base": rel_path, "count": len(entries), "entries": entries})

    # ── read_source ─────────────────────────────────────────────────────
    elif name == "read_source":
        if not _require_model():
            return _error("No analysis loaded.")
        sha = _current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        file_path = sources_dir / arguments["path"]
        # Security: prevent path traversal
        try:
            file_path.resolve().relative_to(sources_dir.resolve())
        except ValueError:
            return _error("Path traversal not allowed.")
        if not file_path.exists():
            return _error(f"File not found: {arguments['path']}")
        content = file_path.read_text(errors="replace")
        lines = content.splitlines()
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 200)
        page = lines[offset:offset + limit]
        return _json({
            "path": arguments["path"],
            "total_lines": len(lines),
            "offset": offset,
            "lines": len(page),
            "has_more": offset + limit < len(lines),
            "content": "\n".join(page),
        })

    # ── read_cache ──────────────────────────────────────────────────────
    elif name == "read_cache":
        if not _require_model():
            return _error("No analysis loaded.")
        category = arguments["category"]
        if not _is_allowed_category(category):
            return _error(
                f"Category '{category}' is not in the allow-list. "
                f"Allowed: {sorted(_ALLOWED_CACHE_CATEGORIES)} + prefixes {list(_ALLOWED_CACHE_PREFIXES)}"
            )
        data = engine.cache.get_json(_current_model.binary.sha256, category)
        if data is None:
            return _error(f"No cached data for category '{category}'. Use list_artifacts to see available keys.")
        return _json({"category": category, "data": data})

    # ── list_artifacts ──────────────────────────────────────────────────
    elif name == "list_artifacts":
        if not _require_model():
            return _error("No analysis loaded.")
        sha = _current_model.binary.sha256
        artifacts = {"cache": [], "directories": []}

        # Cache entries
        cache_dir = engine.cache._entry_dir(sha)
        if cache_dir.exists():
            for f in sorted(cache_dir.iterdir()):
                if f.is_file():
                    artifacts["cache"].append({
                        "key": f.name,
                        "size": f.stat().st_size,
                    })

        # On-disk output directories
        sha_short = sha[:12]
        for label, path in [
            ("unpacked", engine.config.project_dir / "unpacked" / sha_short),
            ("jadx_sources", engine.config.project_dir / "jadx" / sha_short / "sources"),
            ("jadx_resources", engine.config.project_dir / "jadx" / sha_short / "resources"),
            ("ghidra", engine.config.project_dir / "ghidra"),
            ("headers", engine.config.project_dir / "headers" / sha_short),
        ]:
            if path.exists():
                file_count = sum(1 for _ in path.rglob("*") if _.is_file())
                artifacts["directories"].append({"name": label, "path": str(path), "files": file_count})

        return _json(artifacts)

    # ── get_disassembly ─────────────────────────────────────────────────
    elif name == "get_disassembly":
        if not _require_model():
            return _error("No analysis loaded.")
        func = _current_model.get_function(arguments["address"])
        if not func:
            return _error(f"Function {arguments['address']} not found.")
        instructions = getattr(func, "disassembly", None) or []
        return _json({
            "address": func.address, "name": func.name,
            "instruction_count": len(instructions),
            "instructions": instructions,
        })

    # ── get_class_headers ───────────────────────────────────────────────
    elif name == "get_class_headers":
        if not _require_model():
            return _error("No analysis loaded.")
        sha = _current_model.binary.sha256[:12]
        headers_dir = engine.config.project_dir / "headers" / sha
        if not headers_dir.exists():
            return _error("No class-dump headers found. iOS analysis with class-dump must have run.")
        target_file = arguments.get("file")
        if target_file:
            header_path = headers_dir / target_file
            try:
                header_path.resolve().relative_to(headers_dir.resolve())
            except ValueError:
                return _error("Path traversal not allowed.")
            if not header_path.exists():
                return _error(f"Header not found: {target_file}")
            return _json({"file": target_file, "content": header_path.read_text(errors="replace")})
        # List all headers
        headers = sorted(headers_dir.glob("*.h"))
        return _json({
            "count": len(headers),
            "headers": [{"name": h.name, "size": h.stat().st_size} for h in headers[:200]],
        })

    # ── list_packages ───────────────────────────────────────────────────
    elif name == "list_packages":
        device_id = arguments["device_id"]
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    packages = await mgr.list_packages(device_id)
                    await mgr.cleanup()
                    return _json({"device_id": device_id, "count": len(packages), "packages": packages})
                except (OSError, RuntimeError):
                    pass
                await mgr.cleanup()
        return _error(f"Cannot list packages on device {device_id}. Check connection.")

    # ── get_logcat ──────────────────────────────────────────────────────
    elif name == "get_logcat":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return _error("ADB not found. logcat is Android-only.")
        device_id = arguments["device_id"]
        package = arguments["package"]
        lines = arguments.get("lines", 100)
        output = await mgr.logcat(device_id, package, lines)
        await mgr.cleanup()
        return _json({"device_id": device_id, "package": package, "lines": output})

    # ── setup_proxy ─────────────────────────────────────────────────────
    elif name == "setup_proxy":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return _error("ADB not found.")
        ok = await mgr.setup_proxy(arguments["device_id"], arguments["host"], arguments["port"])
        await mgr.cleanup()
        return _json({"status": "ok" if ok else "failed",
                       "proxy": f"{arguments['host']}:{arguments['port']}"})

    # ── clear_proxy ─────────────────────────────────────────────────────
    elif name == "clear_proxy":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return _error("ADB not found.")
        ok = await mgr.clear_proxy(arguments["device_id"])
        await mgr.cleanup()
        return _json({"status": "ok" if ok else "failed"})

    # ── start_frida_server ──────────────────────────────────────────────
    elif name == "start_frida_server":
        device_id = arguments["device_id"]
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    ok = await mgr.start_frida_server(device_id)
                    await mgr.cleanup()
                    if ok:
                        return _json({"status": "running", "device_id": device_id})
                except (OSError, RuntimeError) as e:
                    await mgr.cleanup()
                    return _error(f"Failed to start frida-server: {e}")
        return _error("No device manager available. Install ADB or libimobiledevice.")

    # ── frida_spawn ─────────────────────────────────────────────────────
    elif name == "frida_spawn":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed. Install via: pip install frida frida-tools")
        package = arguments["package"]
        device_id = arguments.get("device_id")
        script = arguments.get("script")
        session = await frida.spawn(package, device_id, script)
        if not session:
            return _error(f"Failed to spawn {package}. Check device connection and frida-server.")
        return _json({"status": "spawned", "session_key": package,
                       "hint": "Use frida_load_script to inject hooks, frida_messages to read output."})

    # ── frida_attach ────────────────────────────────────────────────────
    elif name == "frida_attach":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed.")
        target = arguments["target"]
        device_id = arguments.get("device_id")
        # Try as PID if numeric
        try:
            target_val = int(target)
        except ValueError:
            target_val = target
        session = await frida.attach(target_val, device_id)
        if not session:
            return _error(f"Failed to attach to {target}. Is the app running?")
        return _json({"status": "attached", "session_key": str(target),
                       "hint": "Use frida_load_script or frida_exec to instrument."})

    # ── frida_exec ──────────────────────────────────────────────────────
    elif name == "frida_exec":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return _error(f"No active session '{session_key}'. Use frida_attach or frida_spawn first.")
        result = await session.evaluate(arguments["code"])
        return _json({"session_key": session_key, "result": result})

    # ── frida_load_script ───────────────────────────────────────────────
    elif name == "frida_load_script":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return _error(f"No active session '{session_key}'.")
        await session.load_script(arguments["script"])
        return _json({"status": "loaded", "session_key": session_key})

    # ── frida_messages ──────────────────────────────────────────────────
    elif name == "frida_messages":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return _error(f"No active session '{session_key}'.")
        since = arguments.get("since", 0)
        messages = session.messages[since:]
        return _json({
            "session_key": session_key,
            "total": len(session.messages),
            "since": since,
            "new_count": len(messages),
            "messages": messages[:100],
        })

    # ── frida_detach ────────────────────────────────────────────────────
    elif name == "frida_detach":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return _error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.pop(session_key, None)
        if not session:
            return _error(f"No active session '{session_key}'.")
        await session.detach()
        return _json({"status": "detached", "session_key": session_key})

    # ── start_fuzz ──────────────────────────────────────────────────────
    elif name == "start_fuzz":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return _error("AFL++ (afl-fuzz) is not installed.")
        result = await afl.analyze(arguments["binary"], {
            "input_dir": arguments["input_dir"],
            "output_dir": arguments["output_dir"],
            "duration": arguments.get("duration", 300),
            "qemu": arguments.get("qemu", True),
        })
        return _json(result)

    # ── fuzz_status ─────────────────────────────────────────────────────
    elif name == "fuzz_status":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return _error("AFL++ not installed.")
        result = await afl.get_campaign_status(arguments["campaign_id"])
        return _json(result)

    # ── get_config ──────────────────────────────────────────────────────
    elif name == "get_config":
        updates = arguments.get("set")
        if updates:
            config = engine.config
            allowed = {"skip_dynamic", "skip_fuzzing", "ghidra_max_mem", "adb_device", "ios_udid", "ghidra_home"}
            applied = {}
            for k, v in updates.items():
                if k in allowed and hasattr(config, k):
                    setattr(config, k, v)
                    applied[k] = v
            return _json({"updated": applied})
        # Read config
        config = engine.config
        return _json({
            "project_dir": str(config.project_dir),
            "cache_dir": str(config.cache_dir),
            "ghidra_home": config.ghidra_home,
            "ghidra_max_mem": config.ghidra_max_mem,
            "skip_dynamic": config.skip_dynamic,
            "skip_fuzzing": config.skip_fuzzing,
            "adb_device": config.adb_device,
            "ios_udid": config.ios_udid,
        })

    return _error(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
