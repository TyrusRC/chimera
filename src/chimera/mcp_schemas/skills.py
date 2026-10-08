"""MCP tool schemas: RE skill catalogue."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="list_skills",
             description="List chimera's reusable RE skills (name + description). Works on any MCP host, including tools-only ones.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_skill",
             description="Get the full markdown body of one chimera skill by name (kebab-case, e.g. 're-workflow').",
             inputSchema={"type": "object", "properties": {
                 "name": {"type": "string", "description": "Skill name, kebab-case"},
             }, "required": ["name"]}),
    ]
