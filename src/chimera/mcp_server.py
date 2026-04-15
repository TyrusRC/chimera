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

def _get_engine() -> ChimeraEngine:
    global _engine
    if _engine is None:
        _engine = ChimeraEngine(ChimeraConfig())
    return _engine

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="analyze", description="Analyze a mobile app binary (APK/IPA). Returns summary with finding counts. Must be called before other query tools.",
             inputSchema={"type": "object", "properties": {"path": {"type": "string", "description": "Absolute path to APK or IPA file"}}, "required": ["path"]}),
        Tool(name="get_info", description="Get metadata about the currently loaded binary (platform, framework, format, sha256). Requires prior analyze call.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_findings", description="Get vulnerability findings. Filter by severity or rule_id. Returns up to 50 findings.",
             inputSchema={"type": "object", "properties": {"severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}, "rule_id": {"type": "string"}}}),
        Tool(name="get_functions", description="List functions from analyzed binary. Search by name substring, filter by classification.",
             inputSchema={"type": "object", "properties": {"search": {"type": "string", "description": "Substring to search in function names"}, "classification": {"type": "string"}, "limit": {"type": "integer", "default": 50}}}),
        Tool(name="get_function", description="Get detailed info about a specific function including decompiled code, callers, and callees.",
             inputSchema={"type": "object", "properties": {"address": {"type": "string", "description": "Function address (hex string like 0x1234)"}}, "required": ["address"]}),
        Tool(name="get_strings", description="Search strings extracted from the binary. Use pattern for regex filtering.",
             inputSchema={"type": "object", "properties": {"pattern": {"type": "string", "description": "Regex pattern to filter strings"}, "limit": {"type": "integer", "default": 100}}}),
        Tool(name="get_callgraph", description="Get call graph (callers + callees) around a function up to specified depth.",
             inputSchema={"type": "object", "properties": {"address": {"type": "string"}, "depth": {"type": "integer", "default": 2}}, "required": ["address"]}),
        Tool(name="detect_protections", description="Detect security protections (root detection, anti-frida, SSL pinning, etc) from the current analysis.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_sdks", description="Identify third-party SDKs by matching function package names against known SDK signatures.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_framework", description="Get the detected cross-platform framework (Flutter, React Native, Xamarin, Unity, Cordova, or native).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_bypass_scripts", description="Get Frida bypass scripts for detected protections. Returns combined JS script ready to load.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="export_report", description="Export full analysis as SARIF, JSON, or Markdown report.",
             inputSchema={"type": "object", "properties": {"format": {"type": "string", "enum": ["sarif", "json", "markdown"], "default": "sarif"}}}),
        Tool(name="list_devices", description="List connected Android (ADB) and iOS (libimobiledevice) devices.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="search_finding_evidence", description="Search for a pattern across all finding evidence and descriptions. Useful for investigating specific vulnerability classes.",
             inputSchema={"type": "object", "properties": {"pattern": {"type": "string", "description": "Text to search for in finding titles, descriptions, and evidence"}}, "required": ["pattern"]}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    global _current_model
    engine = _get_engine()

    if name == "analyze":
        path = arguments["path"]
        model = await engine.analyze(path)
        _current_model = model
        findings = getattr(model, "findings", [])
        return [TextContent(type="text", text=json.dumps({
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
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
            },
            "hint": "Use get_findings, get_functions, detect_protections to explore results.",
        }, indent=2))]

    elif name == "get_info":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded. Call analyze first."}')]
        b = _current_model.binary
        return [TextContent(type="text", text=json.dumps({
            "path": str(b.path),
            "sha256": b.sha256,
            "platform": b.platform.value,
            "format": b.format.value,
            "arch": b.arch.value,
            "framework": b.framework.value,
            "size_bytes": b.size_bytes,
            "package_name": b.package_name,
            "functions": len(_current_model.functions),
            "strings": len(_current_model.get_strings()),
            "findings": len(getattr(_current_model, "findings", [])),
        }, indent=2))]

    elif name == "get_findings":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded. Call analyze first."}')]
        findings = getattr(_current_model, "findings", [])
        severity = arguments.get("severity")
        rule_id = arguments.get("rule_id")
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        if rule_id:
            findings = [f for f in findings if f.rule_id == rule_id]
        return [TextContent(type="text", text=json.dumps({
            "total": len(findings),
            "findings": [f.to_dict() for f in findings[:50]],
        }, indent=2))]

    elif name == "get_functions":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        funcs = _current_model.functions
        search = arguments.get("search")
        classification = arguments.get("classification")
        limit = arguments.get("limit", 50)
        if search:
            search = search.lower()
            funcs = [f for f in funcs if search in f.name.lower()]
        if classification:
            funcs = [f for f in funcs if f.classification == classification]
        return [TextContent(type="text", text=json.dumps({
            "total": len(funcs),
            "functions": [
                {"address": f.address, "name": f.name, "classification": f.classification,
                 "layer": f.layer, "has_decompiled": f.decompiled is not None}
                for f in funcs[:limit]
            ],
        }, indent=2))]

    elif name == "get_function":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        func = _current_model.get_function(arguments["address"])
        if not func:
            return [TextContent(type="text", text=f'{{"error": "Function {arguments["address"]} not found"}}')]
        callees = _current_model.get_callees(func.address)
        callers = _current_model.get_callers(func.address)
        return [TextContent(type="text", text=json.dumps({
            "address": func.address, "name": func.name, "language": func.language,
            "classification": func.classification, "layer": func.layer,
            "source_backend": func.source_backend,
            "decompiled": func.decompiled,
            "signature": func.signature,
            "callees": [{"address": c.address, "name": c.name} for c in callees],
            "callers": [{"address": c.address, "name": c.name} for c in callers],
        }, indent=2))]

    elif name == "get_strings":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 100)
        strings = _current_model.get_strings(pattern=pattern)[:limit]
        return [TextContent(type="text", text=json.dumps({
            "total": len(_current_model.get_strings(pattern=pattern)),
            "strings": [{"address": s.address, "value": s.value, "section": s.section} for s in strings],
        }, indent=2))]

    elif name == "get_callgraph":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        address = arguments["address"]
        depth = min(arguments.get("depth", 2), 10)
        nodes, edges = [], []
        visited = set()
        def walk(addr, d):
            if addr in visited or d > depth: return
            visited.add(addr)
            func = _current_model.get_function(addr)
            if not func: return
            nodes.append({"address": addr, "name": func.name, "classification": func.classification})
            for c in _current_model.get_callees(addr):
                edges.append({"from": addr, "to": c.address, "type": "calls"})
                walk(c.address, d + 1)
            for c in _current_model.get_callers(addr):
                edges.append({"from": c.address, "to": addr, "type": "calls"})
                if d < 1:  # Only walk callers at depth 0-1 to avoid explosion
                    walk(c.address, d + 1)
        walk(address, 0)
        return [TextContent(type="text", text=json.dumps({"nodes": nodes, "edges": edges, "center": address}, indent=2))]

    elif name == "detect_protections":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded. Call analyze first."}')]
        from chimera.bypass.detector import ProtectionDetector
        strings = [s.value for s in _current_model.get_strings()]
        profile = ProtectionDetector().detect_from_strings(strings, _current_model.binary.platform.value)
        return [TextContent(type="text", text=json.dumps({
            "root_detection": profile.has_root_detection,
            "jailbreak_detection": profile.has_jailbreak_detection,
            "anti_frida": profile.has_anti_frida,
            "anti_debug": profile.has_anti_debug,
            "ssl_pinning": profile.has_ssl_pinning,
            "integrity": profile.has_integrity_check,
            "packer": profile.has_packer,
            "packer_name": profile.packer_name,
            "has_any_protection": profile.has_any_protection,
            "bypass_order": profile.bypass_order(),
            "details": profile.details[:20],
        }, indent=2))]

    elif name == "detect_sdks":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        from chimera.sdk.analyzer import SDKAnalyzer
        packages = set()
        for func in _current_model.functions:
            if "." in func.name:
                packages.add(func.name.rsplit(".", 1)[0])
        analyzer = SDKAnalyzer()
        detected = analyzer.detect_from_packages(list(packages))
        return [TextContent(type="text", text=json.dumps(analyzer.summarize(detected), indent=2))]

    elif name == "detect_framework":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
        return [TextContent(type="text", text=json.dumps({
            "framework": _current_model.binary.framework.value,
        }))]

    elif name == "get_bypass_scripts":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded. Call analyze first."}')]
        from chimera.bypass.detector import ProtectionDetector
        from chimera.bypass.orchestrator import BypassOrchestrator
        strings = [s.value for s in _current_model.get_strings()]
        platform = _current_model.binary.platform.value
        profile = ProtectionDetector().detect_from_strings(strings, platform)
        if not profile.has_any_protection:
            return [TextContent(type="text", text=json.dumps({
                "has_protections": False,
                "message": "No protections detected — bypass scripts not needed.",
            }))]
        orchestrator = BypassOrchestrator()
        chain = orchestrator.build_bypass_chain(profile, platform)
        combined = orchestrator.get_combined_script(profile, platform)
        return [TextContent(type="text", text=json.dumps({
            "has_protections": True,
            "bypass_order": profile.bypass_order(),
            "scripts": [{"name": s["name"], "type": s["type"]} for s in chain],
            "combined_script": combined,
        }, indent=2))]

    elif name == "export_report":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
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
        return [TextContent(type="text", text=json.dumps(devices, indent=2))]

    elif name == "search_finding_evidence":
        if not _current_model:
            return [TextContent(type="text", text='{"error": "No analysis loaded."}')]
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
        return [TextContent(type="text", text=json.dumps({
            "pattern": arguments["pattern"],
            "matches": len(matched),
            "findings": matched[:30],
        }, indent=2))]

    return [TextContent(type="text", text=f'{{"error": "Unknown tool: {name}"}}')]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
