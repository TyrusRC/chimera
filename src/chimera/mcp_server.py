"""Chimera MCP Server — exposes RE capabilities as tools for LLMs.

This module is only the wiring: it advertises the tool schemas and routes
a call to the handler group that owns it. The tools themselves live in
`chimera.mcp_handlers.*`, grouped by what they need to do their job —
static analysis, on-disk artifacts, an attached device, or the runtime —
and the session state they share lives in `chimera.mcp_session`.
"""
from __future__ import annotations

import asyncio
import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from chimera import mcp_session as mcpstate
from chimera.mcp_handlers import (
    analysis, annotations, artifacts, device, runtime, unpacking,
)
from chimera.mcp_schemas import all_tools

logger = logging.getLogger(__name__)
server = Server("chimera")

#: Tried in order; the first group that owns `name` answers. Each returns
#: None for a tool it does not handle, so adding a group is a one-line
#: change here rather than an edit to a shared dispatch chain.
_HANDLER_GROUPS = (analysis, annotations, artifacts, device, runtime, unpacking)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return all_tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    # Built here rather than in each handler so a tool that never touches
    # the engine still gets a consistent session, and the cost is paid once.
    mcpstate.get_engine()

    for group in _HANDLER_GROUPS:
        result = await group.dispatch(name, arguments)
        if result is not None:
            return result
    return mcpstate.error(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
