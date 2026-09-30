"""Serve chimera's on-disk skills over MCP.

Filesystem-discovery hosts (Claude Code, dsh's skill-filesystem) read the
skills tree directly; these tools make the same skills reachable on hosts
that bridge MCP *tools only*. Read-only; a skill name must be a single
kebab-case component (no path separators, no traversal).
"""
from __future__ import annotations

import re

from mcp.types import TextContent

from chimera import mcp_session as mcpstate
from chimera.integrations.skills_root import skills_root

_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _frontmatter_desc(text: str) -> str:
    if text.startswith("---"):
        end = text.find("\n---", 3)
        for line in text[3:end if end > 0 else 0].splitlines():
            if line.strip().startswith("description:"):
                return line.split("description:", 1)[1].strip()
    return ""


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    root = skills_root()

    if name == "list_skills":
        if root is None:
            return mcpstate.json_reply({"skills": []})
        catalog = []
        for sub in sorted(root.iterdir()):
            md = sub / "SKILL.md"
            if md.is_file():
                catalog.append(
                    {"name": sub.name, "description": _frontmatter_desc(md.read_text())}
                )
        return mcpstate.json_reply({"skills": catalog})

    if name == "get_skill":
        skill = (arguments or {}).get("name", "")
        if not _NAME_RE.match(skill):
            return mcpstate.error(f"Invalid skill name: {skill!r}")
        if root is None:
            return mcpstate.error("No skills directory found.")
        md = root / skill / "SKILL.md"
        if not md.is_file():
            return mcpstate.error(f"Unknown skill: {skill}")
        return mcpstate.json_reply({"name": skill, "body": md.read_text()})

    return None
