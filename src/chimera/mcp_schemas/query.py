"""MCP tool schemas: read-only queries: functions, strings, call graph, manifest, sources, disasm."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
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
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 100},
             }}),
        Tool(name="get_callgraph",
             description="Get call graph around a function (callers + callees) up to specified depth.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string"}, "depth": {"type": "integer", "default": 2},
                 "max_nodes": {"type": "integer", "default": 200,
                               "description": "Cap on nodes returned; response sets truncated=true if hit."},
             }, "required": ["address"]}),
        Tool(name="get_manifest",
             description="Get the decoded AndroidManifest.xml content (Android only). Useful for reviewing permissions, components, intent-filters.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_manifest_findings",
             description="AndroidManifest + network_security_config findings (debuggable, allowBackup, exported components, cleartext traffic, user-CA trust). Requires a prior analyze(path=...) call so the manifest XML is in cache.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="diff_projects",
             description=(
                 "Diff two cached chimera projects. Returns added/removed permissions, "
                 "exported components, SDK packages, native libs, and manifest+NSC findings. "
                 "Inputs are sha256 hashes or prefixes (>=8 chars). Both projects must be "
                 "cached — call analyze(path=...) on each first."
             ),
             inputSchema={"type": "object",
                          "properties": {
                              "a": {"type": "string", "description": "sha256 or prefix of project A"},
                              "b": {"type": "string", "description": "sha256 or prefix of project B"},
                          },
                          "required": ["a", "b"]}),
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
             description="Get disassembly instructions for a function by address. Paged: use offset/limit for long functions.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 200},
             }, "required": ["address"]}),
        Tool(name="get_class_headers",
             description="Read ObjC class-dump headers from iOS analysis. Lists header files or reads a specific header.",
             inputSchema={"type": "object", "properties": {
                 "file": {"type": "string", "description": "Header filename to read (e.g. 'AppDelegate.h'). Omit to list all headers."},
             }}),
        Tool(name="objc_xref",
             description=(
                 "Query the ObjC cross-reference graph (iOS only). Pass selector alone "
                 "to find all classes implementing it. Pass class_name+selector to scope "
                 "the lookup. Pass imp_address to query by IMP address — if imp_address "
                 "is given, selector/class_name are ignored. Returns matching methods "
                 "with callers, category, protocol, and class-dump-enriched signatures. "
                 "Use this instead of get_functions/get_class_headers when you need "
                 "selector → implementation → caller lookups."
             ),
             inputSchema={"type": "object", "properties": {
                 "selector": {"type": "string", "description": "ObjC selector, e.g. 'authenticate:'"},
                 "class_name": {"type": "string", "description": "Optional class to scope"},
                 "imp_address": {"type": "string", "description": "Optional IMP address"},
             }}),
    ]
