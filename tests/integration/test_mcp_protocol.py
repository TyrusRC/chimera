"""Real MCP protocol test: launches `chimera mcp` as a subprocess and
drives it with the official mcp SDK client — the same handshake any
MCP-compatible client (Claude Code, Claude Desktop, ...) performs.

Unlike tests/unit/test_mcp_server.py (which only unit-tests two helper
functions), this proves the server actually speaks MCP: initializes,
lists its tools, and completes a real tool call end to end. No API key
needed — the client here is the protocol library, not an LLM.
"""
from __future__ import annotations

import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "chimera", "mcp"])


@pytest.mark.asyncio
async def test_mcp_server_lists_tools():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            names = {tool.name for tool in result.tools}
            # A handful of tools that must exist for any client to be useful.
            assert {"status", "analyze", "get_functions", "get_strings"} <= names


@pytest.mark.asyncio
async def test_mcp_server_calls_status_tool():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("status", {})
            assert not result.isError
            assert len(result.content) >= 1
            assert result.content[0].type == "text"
