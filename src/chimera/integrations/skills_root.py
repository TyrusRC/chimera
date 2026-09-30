"""Resolve the absolute skills directory across dev checkout and wheel.

Order: explicit env override, then the packaged ``chimera/_skills`` (shipped
in the wheel via force-include), then a dev checkout's ``.claude/skills``
found by walking up from this module. Single source of skill files — the
wheel copy is generated from ``.claude/skills`` at build time.
"""
from __future__ import annotations

import os
from pathlib import Path


def skills_root() -> Path | None:
    env = os.environ.get("CHIMERA_SKILLS_DIR")
    if env:
        p = Path(env)
        return p if p.is_dir() else None

    packaged = Path(__file__).resolve().parent.parent / "_skills"
    if packaged.is_dir():
        return packaged

    for parent in Path(__file__).resolve().parents:
        cand = parent / ".claude" / "skills"
        if cand.is_dir():
            return cand
    return None
