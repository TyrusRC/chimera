"""Path confinement for client-supplied file paths.

Kept dependency-free (no engine/adapter imports) so it can be reused and unit
tested without pulling the whole analysis stack.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import HTTPException


def analyze_roots() -> list[Path]:
    """Directories a client-supplied analyze `path` may live under.

    Defaults to the upload staging dir, the server CWD, and the system temp
    dir (covers the upload→analyze flow and test fixtures). Extend with
    `CHIMERA_ANALYZE_ROOTS` (os.pathsep-separated) for other trusted stores.
    """
    roots = [
        Path(os.environ.get("CHIMERA_UPLOAD_DIR", str(Path.home() / ".chimera" / "uploads"))),
        Path.cwd(),
        Path(tempfile.gettempdir()),
    ]
    extra = os.environ.get("CHIMERA_ANALYZE_ROOTS", "")
    roots += [Path(p) for p in extra.split(os.pathsep) if p.strip()]
    return roots


def assert_analyzable_path(path: Path) -> None:
    """Raise HTTP 403 unless `path` resolves under one of the permitted roots.

    Prevents `POST /api/projects {"path": "/etc/shadow"}` from reading arbitrary
    server files via the analyze endpoint.
    """
    resolved = path.resolve()
    for root in analyze_roots():
        try:
            resolved.relative_to(root.resolve())
            return
        except (ValueError, OSError):
            continue
    raise HTTPException(
        status_code=403,
        detail="path is outside the permitted analyze roots; upload the file "
               "via POST /api/projects/upload or set CHIMERA_ANALYZE_ROOTS.",
    )
