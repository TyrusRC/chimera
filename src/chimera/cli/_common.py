"""chimera.cli —  common commands."""

from __future__ import annotations

import logging
from pathlib import Path



logger = logging.getLogger(__name__)



def _load_cache_and_sha(path: str, project_dir: str | None, cache_dir: str | None):
    """Load the cache and resolve the binary's sha256.

    Helper for CLI commands that need to look up cached analyzer outputs
    by sha256 (e.g. ``chimera manifest``). Computes sha256 directly with
    hashlib so we don't have to spin up the full engine just to read a
    blob out of cache.
    """
    import hashlib
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    cache = AnalysisCache(config.cache_dir)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return cache, h.hexdigest()
