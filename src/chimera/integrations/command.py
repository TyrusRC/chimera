"""Build the one stdio launch command every host runs.

Two forms: the repo's mcp-launch.sh wrapper for a local checkout (baked
absolute path), or a no-clone ``uvx --from git+…`` form. Only the wrapping
config differs per host; this command does not.
"""
from __future__ import annotations

from pathlib import Path

_UVX_ARGS = [
    "--from",
    "git+https://github.com/TyrusRC/chimera",
    "chimera",
    "mcp",
]


def _find_repo_root(start: Path) -> Path | None:
    for p in [start, *start.parents]:
        if (p / "scripts" / "mcp-launch.sh").exists() and (p / ".venv").exists():
            return p
    return None


def build_launch_command(
    *, portable: bool = False, repo_root: Path | None = None
) -> dict:
    if not portable:
        root = repo_root or _find_repo_root(Path(__file__).resolve())
        if root is not None:
            return {
                "command": str(root / "scripts" / "mcp-launch.sh"),
                "args": ["mcp"],
                "env": {},
            }
    return {"command": "uvx", "args": list(_UVX_ARGS), "env": {}}
