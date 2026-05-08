"""Parse Volatility 3 file-cache plugin output.

Plugin: `linux.pagecache.Files`. Each row reports a file the kernel had
cached at acquisition time. We record the path + inode + size and let
downstream callers cross-reference with persistence patterns.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class CachedFile:
    inode: Optional[int]
    path: str
    size: Optional[int] = None
    mode: Optional[str] = None       # rwxr-xr-x or octal-string

    def to_dict(self) -> dict[str, Any]:
        return {
            "inode": self.inode,
            "path": self.path,
            "size": self.size,
            "mode": self.mode,
        }


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_pagecache_files(rows: list[dict]) -> list[CachedFile]:
    out: list[CachedFile] = []
    for row in rows or []:
        path = row.get("Path") or row.get("FilePath") or row.get("File") or ""
        if not path:
            continue
        out.append(CachedFile(
            inode=_to_int(row.get("Inode") or row.get("InodeNumber")),
            path=str(path),
            size=_to_int(row.get("Size") or row.get("Length")),
            mode=str(row.get("Mode") or row.get("Permissions") or "") or None,
        ))
    return out
