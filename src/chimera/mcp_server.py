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
        Tool(name="analyze", description="Analyze a mobile app binary (APK/IPA). Returns full analysis with findings.",
             inputSchema={"type": "object", "properties": {"path": {"type": "string", "description": "Path to APK or IPA file"}}, "required": ["path"]}),
        Tool(name="get_info", description="Get binary metadata, platform, framework, protection profile.",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
        Tool(name="get_findings", description="Get vulnerability findings from the last analysis.",
             inputSchema={"type": "object", "properties": {"severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]}, "rule_id": {"type": "string"}}}),
        Tool(name="get_functions", description="List functions from analyzed binary. Supports search and classification filter.",
             inputSchema={"type": "object", "properties": {"search": {"type": "string"}, "classification": {"type": "string"}, "limit": {"type": "integer", "default": 50}}}),
        Tool(name="get_function", description="Get detailed info about a specific function including decompiled code.",
             inputSchema={"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}),
        Tool(name="get_strings", description="Search strings in the analyzed binary.",
             inputSchema={"type": "object", "properties": {"pattern": {"type": "string"}, "limit": {"type": "integer", "default": 100}}}),
        Tool(name="get_callgraph", description="Get call graph around a function.",
             inputSchema={"type": "object", "properties": {"address": {"type": "string"}, "depth": {"type": "integer", "default": 2}}, "required": ["address"]}),
        Tool(name="detect_protections", description="Detect security protections (root detection, anti-frida, SSL pinning, etc).",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
        Tool(name="detect_sdks", description="Identify third-party SDKs in the app.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_framework", description="Detect cross-platform framework (Flutter, React Native, Xamarin, Unity, Cordova).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="export_report", description="Export analysis findings as SARIF, JSON, or Markdown.",
             inputSchema={"type": "object", "properties": {"format": {"type": "string", "enum": ["sarif", "json", "markdown"], "default": "sarif"}}}),
        Tool(name="list_devices", description="List connected Android/iOS devices.",
             inputSchema={"type": "object", "properties": {}}),
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
            "platform": model.binary.platform.value,
            "format": model.binary.format.value,
            "framework": model.binary.framework.value,
            "functions": len(model.functions),
            "strings": len(model.get_strings()),
            "findings": len(findings),
            "findings_summary": {
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
            },
        }, indent=2))]

    elif name == "get_findings":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded. Run analyze first.")]
        findings = getattr(_current_model, "findings", [])
        severity = arguments.get("severity")
        rule_id = arguments.get("rule_id")
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        if rule_id:
            findings = [f for f in findings if f.rule_id == rule_id]
        return [TextContent(type="text", text=json.dumps([f.to_dict() for f in findings[:50]], indent=2))]

    elif name == "get_functions":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
        funcs = _current_model.functions
        search = arguments.get("search")
        classification = arguments.get("classification")
        limit = arguments.get("limit", 50)
        if search:
            search = search.lower()
            funcs = [f for f in funcs if search in f.name.lower()]
        if classification:
            funcs = [f for f in funcs if f.classification == classification]
        return [TextContent(type="text", text=json.dumps([
            {"address": f.address, "name": f.name, "classification": f.classification, "layer": f.layer}
            for f in funcs[:limit]
        ], indent=2))]

    elif name == "get_function":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
        func = _current_model.get_function(arguments["address"])
        if not func:
            return [TextContent(type="text", text=f"Function {arguments['address']} not found")]
        callees = _current_model.get_callees(func.address)
        callers = _current_model.get_callers(func.address)
        return [TextContent(type="text", text=json.dumps({
            "address": func.address, "name": func.name, "language": func.language,
            "classification": func.classification, "decompiled": func.decompiled,
            "callees": [{"addr": c.address, "name": c.name} for c in callees],
            "callers": [{"addr": c.address, "name": c.name} for c in callers],
        }, indent=2))]

    elif name == "get_strings":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 100)
        strings = _current_model.get_strings(pattern=pattern)[:limit]
        return [TextContent(type="text", text=json.dumps([
            {"address": s.address, "value": s.value} for s in strings
        ], indent=2))]

    elif name == "get_callgraph":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
        address = arguments["address"]
        depth = arguments.get("depth", 2)
        nodes, edges = [], []
        visited = set()
        def walk(addr, d):
            if addr in visited or d > depth: return
            visited.add(addr)
            func = _current_model.get_function(addr)
            if not func: return
            nodes.append({"address": addr, "name": func.name, "classification": func.classification})
            for c in _current_model.get_callees(addr):
                edges.append({"from": addr, "to": c.address})
                walk(c.address, d + 1)
        walk(address, 0)
        return [TextContent(type="text", text=json.dumps({"nodes": nodes, "edges": edges}, indent=2))]

    elif name == "detect_protections":
        path = arguments["path"]
        model = await engine.analyze(path)
        _current_model = model
        from chimera.bypass.detector import ProtectionDetector
        strings = [s.value for s in model.get_strings()]
        profile = ProtectionDetector().detect_from_strings(strings, model.binary.platform.value)
        return [TextContent(type="text", text=json.dumps({
            "root_detection": profile.has_root_detection,
            "jailbreak_detection": profile.has_jailbreak_detection,
            "anti_frida": profile.has_anti_frida,
            "anti_debug": profile.has_anti_debug,
            "ssl_pinning": profile.has_ssl_pinning,
            "integrity": profile.has_integrity_check,
            "bypass_order": profile.bypass_order(),
        }, indent=2))]

    elif name == "detect_sdks":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
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
            return [TextContent(type="text", text="No analysis loaded.")]
        return [TextContent(type="text", text=json.dumps({
            "framework": _current_model.binary.framework.value,
        }))]

    elif name == "export_report":
        if not _current_model:
            return [TextContent(type="text", text="No analysis loaded.")]
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
                for d in await mgr.list_devices():
                    devices.append({"id": d.id, "platform": d.platform.value, "model": d.model, "os": d.os_version, "rooted": d.is_rooted})
        return [TextContent(type="text", text=json.dumps(devices, indent=2))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
