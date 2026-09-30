"""OpenAI Codex CLI host — TOML config.

stdlib has no TOML writer, so we emit only our own well-formed
``[mcp_servers.chimera]`` table and splice it in: replace an existing
chimera table in place, else append. Other tables/comments are preserved
verbatim. ``tomllib`` is used to read for idempotency + validation.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from chimera.integrations.base import backup

_HEADER = "[mcp_servers.chimera]"
# Match our table from its header to the next top-level "[" or EOF.
_TABLE_RE = re.compile(r"(?ms)^\[mcp_servers\.chimera\]\s*$.*?(?=^\[|\Z)")


def _render(entry: dict) -> str:
    args = ", ".join(f'"{a}"' for a in entry["args"])
    lines = [_HEADER, f'command = "{entry["command"]}"', f"args = [{args}]"]
    env = entry.get("env") or {}
    if env:
        lines.append("[mcp_servers.chimera.env]")
        lines += [f'{k} = "{v}"' for k, v in env.items()]
    return "\n".join(lines) + "\n"


class CodexHost:
    name = "codex"

    def __init__(self, path: Path | None = None):
        self._path = Path(path) if path else Path.home() / ".codex/config.toml"

    def detect(self) -> bool:
        return self._path.exists() or (Path.home() / ".codex").is_dir()

    def target_path(self) -> Path:
        return self._path

    def _current(self) -> dict | None:
        if not self._path.exists():
            return None
        return tomllib.loads(self._path.read_text()).get("mcp_servers", {}).get("chimera")

    def is_wired(self) -> bool:
        try:
            return self._current() is not None
        except (tomllib.TOMLDecodeError, OSError):
            return False

    def apply(self, entry: dict, *, dry_run: bool) -> str | None:
        desired = {"command": entry["command"], "args": entry["args"]}
        if entry.get("env"):
            desired["env"] = entry["env"]
        if self._current() == desired:
            return None
        summary = f"codex: {self._path} [mcp_servers.chimera]"
        if dry_run:
            return summary
        text = self._path.read_text() if self._path.exists() else ""
        block = _render(entry)
        if _HEADER in text:
            text = _TABLE_RE.sub(block, text, count=1)
        else:
            sep = "" if text.endswith("\n") or text == "" else "\n"
            text = text + sep + ("\n" if text else "") + block
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            backup(self._path)
        self._path.write_text(text)
        return summary
