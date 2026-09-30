"""JSON MCP-config hosts (Claude Code/Desktop, Gemini, Antigravity,
Cursor, Windsurf, VS Code). They differ only by file path and the root
key ("mcpServers" vs VS Code's "servers").
"""
from __future__ import annotations

import json
from pathlib import Path

from chimera.integrations.base import backup


class JsonHost:
    def __init__(self, name: str, path: Path, root_key: str = "mcpServers"):
        self.name = name
        self._path = Path(path)
        self.root_key = root_key

    def detect(self) -> bool:
        # Present if the config file OR its parent dir already exists.
        return self._path.exists() or self._path.parent.is_dir()

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
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            backup(self._path)
        self._path.write_text(json.dumps(data, indent=2) + "\n")
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
        backup(self._path)
        del servers["chimera"]
        data[self.root_key] = servers
        self._path.write_text(json.dumps(data, indent=2) + "\n")
        return True
