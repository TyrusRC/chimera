"""Host-hardware tools: what acceleration is available to this analysis box.

Unlike the device tools, these need no attached phone and no loaded binary —
they answer "what can this machine do" so an agent can decide whether to
offload a crack/keyspace search to the GPU. Read-only.

Returns None when the tool isn't one of this module's, so the server can try
the next handler group.
"""
from __future__ import annotations

import logging

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    if name == "detect_gpu":
        from chimera.hw.gpu import detect_gpu

        report = detect_gpu()
        payload = report.as_dict()
        payload["summary"] = report.summary()
        if report.usable:
            payload["hint"] = (
                "GPU cracking is available. Use the 'gpu-acceleration' skill: "
                "identify the hash/keyspace, then drive hashcat (or john). "
                "Do NOT brute-force a large unknown key with no crib — recover "
                "it analytically instead."
            )
        return mcpstate.json_reply(payload)

    return None
