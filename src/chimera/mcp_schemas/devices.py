"""MCP tool schemas: device inventory + on-device interaction (logcat, proxy, packages)."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="list_devices",
             description="List connected Android (ADB) and iOS (libimobiledevice) devices.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="connect_device",
             description="Attach a networked Android device or emulator over TCP/IP via `adb connect` (adb-over-Wi-Fi to a real ROOT device, or a remote/headless emulator). USB devices and locally-running emulators already appear in list_devices without this. A bare host uses the default adb port :5555. Returns {connected, target, devices, hint}; set disconnect=true to `adb disconnect` instead. The call is time-bounded (adb connect blocks on an unreachable target).",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "host[:port] to connect (bare host → :5555)."},
                 "disconnect": {"type": "boolean", "default": False, "description": "Disconnect the target instead of connecting."},
             }, "required": ["target"]}),
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
        Tool(name="pull_app",
             description="Pull an installed app from a connected device. Returns path to the downloaded APK/IPA.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID from list_devices"},
                 "package": {"type": "string", "description": "Package name (e.g. com.example.app)"},
             }, "required": ["device_id", "package"]}),
    ]
