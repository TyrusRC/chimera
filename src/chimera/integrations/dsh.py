"""DeepSeek Harness (dsh) host.

dsh consumes MCP servers via an ``@deepseek-ai/dsh-mcp-client`` plugin row
in a Cordis patch file, and filesystem skills via ``dsh-skill-filesystem``
``customSkillDirs``. Patch files are additive lists, so we APPEND a
well-formed block (no PyYAML dependency) and treat the presence of
``id: mcp-chimera`` as "already installed".
"""
from __future__ import annotations

from pathlib import Path

from chimera.integrations.base import backup
from chimera.integrations.skills_root import skills_root


class DshHost:
    name = "dsh"

    def __init__(self, path: Path | None = None, skills_dir: Path | None = None):
        self._path = Path(path) if path else Path.home() / ".dsh/cordis.patch.yml"
        self._skills_dir = skills_dir if skills_dir is not None else skills_root()

    def detect(self) -> bool:
        return self._path.exists() or (Path.home() / ".dsh").is_dir()

    def target_path(self) -> Path:
        return self._path

    def is_wired(self) -> bool:
        return self._path.exists() and "id: mcp-chimera" in self._path.read_text()

    def _block(self, entry: dict) -> str:
        args = ", ".join(f"'{a}'" for a in entry["args"])
        lines = [
            "- insert:",
            "    - id: mcp-chimera",
            "      name: '@deepseek-ai/dsh-mcp-client'",
            "      config:",
            "        serverName: chimera",
            "        transport: stdio",
            f"        command: '{entry['command']}'",
            f"        args: [{args}]",
            "        toolCallTimeoutMs: 120000",
        ]
        if self._skills_dir is not None:
            lines += [
                "    - name: '@deepseek-ai/dsh-skill-filesystem'",
                "      config:",
                f"        customSkillDirs: ['{self._skills_dir}']",
            ]
        return "\n".join(lines) + "\n"

    def apply(self, entry: dict, *, dry_run: bool) -> str | None:
        if self.is_wired():
            return None
        summary = f"dsh: {self._path} [+mcp-chimera row]"
        if dry_run:
            return summary
        self._path.parent.mkdir(parents=True, exist_ok=True)
        existing = self._path.read_text() if self._path.exists() else ""
        if self._path.exists():
            backup(self._path)
        sep = "" if existing.endswith("\n") or existing == "" else "\n"
        self._path.write_text(existing + sep + self._block(entry))
        return summary
