"""MCP tool schemas: session + whole-binary analyze + config."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="status",
             description="Show current session state: whether a binary is loaded, what backends are available, analysis stats. Call this first to understand what you can do.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="analyze",
             description="Run full static analysis on a binary. Supports APK, IPA, PE (EXE/DLL), ELF, Mach-O, WASM, DEX, .NET, firmware, and memory images. This is the entry point — must be called before query tools.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Absolute path to the binary file"},
                 "mapping_file": {
                     "type": "string",
                     "description": "Optional ProGuard/R8 mapping.txt path to restore original identifiers",
                 },
             }, "required": ["path"]}),
        Tool(name="get_config",
             description="Get or modify Chimera analysis configuration. Call with no params to read current config.",
             inputSchema={"type": "object", "properties": {
                 "set": {"type": "object", "description": "Key-value pairs to update (e.g. {\"skip_dynamic\": false, \"ghidra_max_mem\": \"8g\"})"},
             }}),
        Tool(name="switch_binary",
             description=(
                 "Switch the active binary in a multi-binary session. "
                 "After analyzing several binaries, query tools read the active one. "
                 "Pass a sha256 prefix (>=8 chars) to switch. "
                 "Use list_binaries to see all loaded targets."
             ),
             inputSchema={"type": "object", "properties": {
                 "sha": {"type": "string",
                         "description": "sha256 prefix (>=8 chars) of the target to activate."},
             }, "required": ["sha"]}),
        Tool(name="list_binaries",
             description="List all binaries loaded in this session (from prior analyze calls). Shows sha256, path, platform, function count, and which is active.",
             inputSchema={"type": "object", "properties": {}}),
    ]
