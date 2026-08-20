"""Locate .NET global tools, including the ones not on PATH.

`dotnet tool install -g` installs into ~/.dotnet/tools and only *prints* a
hint to add that to PATH, so a process started by a non-login shell — a
launched MCP server, a cron job — cannot find `ilspycmd` by name. Checking
the standard global-tools directory as well keeps the .NET decompile
working regardless of shell setup.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def _tools_dir() -> Path:
    override = os.environ.get("DOTNET_TOOLS_DIR")
    if override:
        return Path(override)
    return Path.home() / ".dotnet" / "tools"


def find_dotnet_tool(name: str) -> str | None:
    """Absolute path to a .NET global tool, or None.

    PATH wins; the standard global-tools directory is the fallback.
    """
    on_path = shutil.which(name)
    if on_path:
        return on_path
    candidate = _tools_dir() / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None
