"""Common host contract + backup helper for config writers."""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


def backup(path: Path) -> Path:
    """Copy path -> path.chimera-bak-<UTC-ISO> before first modification."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = path.with_name(path.name + f".chimera-bak-{stamp}")
    shutil.copy2(path, dst)
    return dst


class Host(Protocol):
    name: str

    def detect(self) -> bool: ...
    def target_path(self) -> Path: ...
    def apply(self, entry: dict, *, dry_run: bool) -> str | None: ...
    def is_wired(self) -> bool: ...
