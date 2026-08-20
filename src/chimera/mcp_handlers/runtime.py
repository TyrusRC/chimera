"""Fuzzing control and server configuration.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    engine = mcpstate.get_engine()
    if name == "start_fuzz":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return mcpstate.error("AFL++ (afl-fuzz) is not installed.")
        result = await afl.analyze(arguments["binary"], {
            "input_dir": arguments["input_dir"],
            "output_dir": arguments["output_dir"],
            "duration": arguments.get("duration", 300),
            "qemu": arguments.get("qemu", True),
        })
        return mcpstate.json_reply(result)

    # ── fuzz_status ─────────────────────────────────────────────────────
    if name == "fuzz_status":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return mcpstate.error("AFL++ not installed.")
        result = await afl.get_campaign_status(arguments["campaign_id"])
        return mcpstate.json_reply(result)

    # ── get_config ──────────────────────────────────────────────────────
    if name == "get_config":
        updates = arguments.get("set")
        if updates:
            config = engine.config
            allowed = {"skip_dynamic", "skip_fuzzing", "ghidra_max_mem", "adb_device", "ios_udid", "ghidra_home"}
            applied = {}
            for k, v in updates.items():
                if k in allowed and hasattr(config, k):
                    setattr(config, k, v)
                    applied[k] = v
            return mcpstate.json_reply({"updated": applied})
        # Read config
        config = engine.config
        return mcpstate.json_reply({
            "project_dir": str(config.project_dir),
            "cache_dir": str(config.cache_dir),
            "ghidra_home": config.ghidra_home,
            "ghidra_max_mem": config.ghidra_max_mem,
            "skip_dynamic": config.skip_dynamic,
            "skip_fuzzing": config.skip_fuzzing,
            "adb_device": config.adb_device,
            "ios_udid": config.ios_udid,
        })

    # ── objc_xref ───────────────────────────────────────────────────────
    return None
