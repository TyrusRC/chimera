"""Agent-host registry for `chimera install`."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from chimera.integrations.codex import CodexHost
from chimera.integrations.dsh import DshHost
from chimera.integrations.jsonhost import JsonHost


def _claude_desktop_config(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library/Application Support/Claude/claude_desktop_config.json"
    if sys.platform.startswith("win"):
        return Path(os.environ.get("APPDATA", home)) / "Claude/claude_desktop_config.json"
    return home / ".config/Claude/claude_desktop_config.json"


def build_registry(cwd: Path | None = None, home: Path | None = None) -> dict:
    # Resolved at call time (not import) so callers/tests that chdir or
    # monkeypatch Path.home see the right roots.
    cwd = cwd or Path.cwd()
    home = home or Path.home()
    hosts: dict = {}
    for h in [
        JsonHost("claude-code", cwd / ".mcp.json"),
        JsonHost("claude-desktop", _claude_desktop_config(home)),
        JsonHost("gemini", home / ".gemini/settings.json"),
        JsonHost("antigravity", home / ".gemini/config/mcp_config.json"),
        JsonHost("cursor", cwd / ".cursor/mcp.json"),
        JsonHost("windsurf", home / ".codeium/windsurf/mcp_config.json"),
        JsonHost("vscode", cwd / ".vscode/mcp.json", root_key="servers"),
        DshHost(home / ".dsh/cordis.patch.yml"),
        CodexHost(home / ".codex/config.toml"),
    ]:
        hosts[h.name] = h
    return hosts
