"""SHA256-keyed analysis cache — avoids re-analyzing unchanged binaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class AnalysisCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _entry_dir(self, sha256: str) -> Path:
        return self.cache_dir / sha256[:2] / sha256

    def has(self, sha256: str) -> bool:
        return self._entry_dir(sha256).exists()

    def path_for(self, sha256: str, category: str) -> Path:
        entry = self._entry_dir(sha256)
        return entry / category

    def put(self, sha256: str, category: str, data: bytes) -> Path:
        path = self.path_for(sha256, category)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def get(self, sha256: str, category: str) -> Optional[bytes]:
        path = self.path_for(sha256, category)
        if not path.exists():
            return None
        return path.read_bytes()

    def put_json(self, sha256: str, category: str, data: Any) -> Path:
        return self.put(sha256, category, json.dumps(data, indent=2).encode())

    def get_json(self, sha256: str, category: str) -> Optional[Any]:
        raw = self.get(sha256, category)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            import logging
            logging.getLogger(__name__).warning(
                "cache entry corrupted, dropping: %s/%s (%s)", sha256[:12], category, exc
            )
            return None
