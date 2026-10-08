"""MCP tool schemas: Frida dynamic instrumentation."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
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
    ]
