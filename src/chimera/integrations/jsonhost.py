"""JSON MCP-config hosts (Claude Code/Desktop, Gemini, Antigravity,
Cursor, Windsurf, VS Code). They differ only by file path and the root
key ("mcpServers" vs VS Code's "servers").
"""
from __future__ import annotations

import json
from pathlib import Path

from chimera.integrations.base import write_with_backup


class JsonHost:
    def __init__(self, name: str, path: Path, root_key: str = "mcpServers",
                 markers: list[Path] | None = None):
        self.name = name
        self._path = Path(path)
        self.root_key = root_key
        # A host is "present" if its config file or one of these markers
        # exists. Defaults to the parent dir — fine for a host rooted in its
        # own dir (~/.gemini/…), but a host rooted in an always-present dir
        # (cwd/.mcp.json) must pass explicit markers, or it detects everywhere.
        self._markers = markers if markers is not None else [self._path.parent]

    def detect(self) -> bool:
        return self._path.exists() or any(m.exists() for m in self._markers)

    def target_path(self) -> Path:
        return self._path

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        return json.loads(self._path.read_text() or "{}")

    def is_wired(self) -> bool:
        try:
            return "chimera" in (self._load().get(self.root_key) or {})
        except (json.JSONDecodeError, OSError):
            return False

    def apply(self, entry: dict, *, dry_run: bool) -> str | None:
        data = self._load()
        servers = data.get(self.root_key)
        if not isinstance(servers, dict):
            servers = {}
        if servers.get("chimera") == entry:
            return None
        summary = f"{self.name}: {self._path} [{self.root_key}.chimera]"
        if dry_run:
            return summary
        servers["chimera"] = entry
        data[self.root_key] = servers
        write_with_backup(self._path, json.dumps(data, indent=2) + "\n")
        return summary

    def remove(self, *, dry_run: bool) -> bool:
        if not self._path.exists():
            return False
        data = self._load()
        servers = data.get(self.root_key) or {}
        if "chimera" not in servers:
            return False
        if dry_run:
            return True
        del servers["chimera"]
        data[self.root_key] = servers
        write_with_backup(self._path, json.dumps(data, indent=2) + "\n")
        return True
