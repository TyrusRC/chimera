"""MCP tools for the managed-VM capability.

Thin wrappers over chimera.dynamic.vm providers. Read-mostly control; the one
execution tool (vm_exec) enforces the snapshot-required safety rule: it reverts
to a named snapshot before running, so a sample never runs against a base image.
Guest password comes from the CHIMERA_VM_GUEST_PASSWORD env var, never a param.
"""
from __future__ import annotations

import os

from mcp.types import TextContent

from chimera import mcp_session as mcpstate
from chimera.dynamic.vm import get_provider

_VM_TOOLS = {"vm_list", "vm_snapshot", "vm_revert", "vm_start", "vm_stop",
             "vm_exec", "vm_copy"}


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    if name not in _VM_TOOLS:
        return None
    args = arguments or {}
    prov = get_provider(args.get("provider"))
    if prov is None or not prov.available():
        return mcpstate.json_reply(
            {"available": False,
             "error": "no VM provider available (VirtualBox CLI not found)"})

    if name == "vm_list":
        return mcpstate.json_reply(
            {"available": True,
             "vms": [{"name": v.name, "state": v.state} for v in prov.list()]})
    if name == "vm_snapshot":
        prov.snapshot(args["vm"], args["name"])
        return mcpstate.json_reply({"ok": True})
    if name == "vm_revert":
        prov.revert(args["vm"], args["name"])
        return mcpstate.json_reply({"ok": True})
    if name == "vm_start":
        prov.start(args["vm"], headless=args.get("headless", True))
        return mcpstate.json_reply({"ok": True})
    if name == "vm_stop":
        prov.stop(args["vm"], save=args.get("save", False))
        return mcpstate.json_reply({"ok": True})
    if name == "vm_copy":
        pw = os.environ.get("CHIMERA_VM_GUEST_PASSWORD", "")
        user = args["guest_user"]
        if args.get("direction", "in") == "out":
            prov.copy_out(args["vm"], args["guest_path"], args["host_path"],
                          user=user, password=pw)
        else:
            prov.copy_in(args["vm"], args["host_path"], args["guest_path"],
                         user=user, password=pw)
        return mcpstate.json_reply({"ok": True})
    if name == "vm_exec":
        snapshot = args.get("snapshot")
        if not snapshot:
            return mcpstate.error("vm_exec requires 'snapshot' — it reverts to it "
                                  "first so the sample runs from a clean state.")
        pw = os.environ.get("CHIMERA_VM_GUEST_PASSWORD", "")
        prov.revert(args["vm"], snapshot)
        prov.start(args["vm"])
        res = prov.exec(args["vm"], args["argv"], user=args["guest_user"],
                        password=pw, timeout=args.get("timeout", 120),
                        network=args.get("network", "off"))
        return mcpstate.json_reply({"exit_code": res.exit_code, "stdout": res.stdout,
                                    "stderr": res.stderr, "timed_out": res.timed_out})
    return None
