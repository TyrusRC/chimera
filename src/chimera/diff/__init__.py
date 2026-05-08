"""Binary-vs-binary diff: load two cached projects and compare them."""
from __future__ import annotations

from chimera.diff.engine import NativeLibChange, ProjectDiff, diff_projects
from chimera.diff.loader import (
    ProjectNotInCacheError,
    ProjectSnapshot,
    load_project,
)
from chimera.diff.render import render_json, render_markdown

__all__ = [
    "NativeLibChange",
    "ProjectDiff",
    "ProjectNotInCacheError",
    "ProjectSnapshot",
    "diff_projects",
    "load_project",
    "render_json",
    "render_markdown",
]
