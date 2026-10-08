"""Aggregated MCP tool schemas, split by domain (see the submodules).

The public entry point stays ``from chimera.mcp_schemas import all_tools``.
"""
from __future__ import annotations

from mcp.types import Tool

from . import (
    session,
    query,
    detection,
    vm,
    skills,
    annotate,
    devices,
    frida,
    dynamic,
    unpacking,
    solving,
)

#: submodules whose tools() are concatenated, in advertised order
_MODULES = (
    session,
    query,
    detection,
    vm,
    skills,
    annotate,
    devices,
    frida,
    dynamic,
    unpacking,
    solving,
)


def all_tools() -> list[Tool]:
    tools: list[Tool] = []
    for mod in _MODULES:
        tools.extend(mod.tools())
    return tools
