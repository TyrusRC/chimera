"""MCP tool schemas: QEMU VM lifecycle (snapshot/revert/exec)."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="vm_list",
             description="List managed VMs on the host hypervisor (VirtualBox). Top isolation tier — a real snapshot-capable guest, driven from WSL against the Windows host.",
             inputSchema={"type": "object", "properties": {
                 "provider": {"type": "string", "description": "Provider name; default auto-detect."}}}),
        Tool(name="vm_snapshot",
             description="Take a snapshot of a VM (the clean restore point for detonation).",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "name": {"type": "string"},
                 "provider": {"type": "string"}}, "required": ["vm", "name"]}),
        Tool(name="vm_revert",
             description="Restore a VM to a snapshot (powers it off first).",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "name": {"type": "string"},
                 "provider": {"type": "string"}}, "required": ["vm", "name"]}),
        Tool(name="vm_start",
             description="Power on a VM (headless by default).",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "headless": {"type": "boolean", "default": True},
                 "provider": {"type": "string"}}, "required": ["vm"]}),
        Tool(name="vm_stop",
             description="Power off a VM (or save state).",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "save": {"type": "boolean", "default": False},
                 "provider": {"type": "string"}}, "required": ["vm"]}),
        Tool(name="vm_copy",
             description="Copy a file into or out of a running guest (needs Guest Additions). Guest password from CHIMERA_VM_GUEST_PASSWORD.",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "host_path": {"type": "string"},
                 "guest_path": {"type": "string"}, "guest_user": {"type": "string"},
                 "direction": {"type": "string", "enum": ["in", "out"], "default": "in"},
                 "provider": {"type": "string"}},
                 "required": ["vm", "host_path", "guest_path", "guest_user"]}),
        Tool(name="vm_exec",
             description="Run a program INSIDE a guest and capture its output. Safety: requires 'snapshot' — reverts to it and starts the VM first, so the sample runs from a clean state. Network off by default. Guest password from CHIMERA_VM_GUEST_PASSWORD.",
             inputSchema={"type": "object", "properties": {
                 "vm": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
                 "snapshot": {"type": "string", "description": "Clean snapshot to revert to first (required)."},
                 "guest_user": {"type": "string"},
                 "timeout": {"type": "integer", "default": 120},
                 "network": {"type": "string", "enum": ["off", "hostonly", "nat"], "default": "off"},
                 "provider": {"type": "string"}},
                 "required": ["vm", "argv", "snapshot", "guest_user"]}),
    ]
