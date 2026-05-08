"""Load a cached chimera project into a typed snapshot.

The snapshot is whatever the diff engine needs to compare two projects:
manifest+NSC bytes, jadx packages, native-lib triage, and the project's
identity (sha256 + filename).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from chimera.core.cache import AnalysisCache


_SHA256_RE = re.compile(r"^[0-9a-f]{1,64}$", re.IGNORECASE)


class ProjectNotInCacheError(LookupError):
    """Raised when no cached project matches the given spec."""


@dataclass
class ProjectSnapshot:
    sha256: str
    manifest_xml: Optional[bytes] = None
    nsc_xml: Optional[bytes] = None
    jadx_packages: list[str] = field(default_factory=list)
    native_libs: dict[str, dict] = field(default_factory=dict)  # libname -> r2 triage


def _resolve_sha(spec: str, cache: AnalysisCache) -> str:
    """Resolve a sha256 / sha256-prefix to a full sha256 from cache directory."""
    spec = spec.strip().lower()
    if not spec or not _SHA256_RE.match(spec):
        raise ValueError(f"not a sha256 or prefix: {spec!r}")

    if len(spec) == 64:
        if not cache.has(spec):
            raise ProjectNotInCacheError(spec)
        return spec

    # Prefix lookup: scan matching buckets under cache_dir/. Each bucket is
    # named after the first 2 chars of a sha256, so we only scan buckets
    # whose name is consistent with `spec` (≥2 chars: exact bucket; 1 char:
    # all buckets starting with that char).
    if not cache.cache_dir.exists():
        raise ProjectNotInCacheError(spec)

    bucket_prefix = spec[:2]
    candidate_buckets = [
        b for b in cache.cache_dir.iterdir()
        if b.is_dir() and b.name.startswith(bucket_prefix) and len(b.name) == 2
    ]

    matches: list[str] = []
    for bucket in candidate_buckets:
        for entry in bucket.iterdir():
            if entry.is_dir() and entry.name.startswith(spec):
                matches.append(entry.name)

    if len(matches) == 0:
        raise ProjectNotInCacheError(spec)
    if len(matches) > 1:
        raise ValueError(f"ambiguous prefix {spec!r}: matches {len(matches)} projects")
    return matches[0]


def load_project(spec: str, cache: AnalysisCache) -> ProjectSnapshot:
    """Load the cached state for a project identified by sha256 or prefix."""
    sha = _resolve_sha(spec, cache)

    snap = ProjectSnapshot(sha256=sha)
    snap.manifest_xml = cache.get(sha, "manifest_xml")
    snap.nsc_xml = cache.get(sha, "nsc_xml")

    jadx = cache.get_json(sha, "jadx")
    if jadx and isinstance(jadx, dict):
        snap.jadx_packages = list(jadx.get("packages") or [])

    # Native libs: any cache key starting with "r2_" is a per-lib triage.
    for key in cache.list_keys(sha):
        if key.startswith("r2_"):
            libname = key[len("r2_"):]
            triage = cache.get_json(sha, key)
            if isinstance(triage, dict):
                snap.native_libs[libname] = triage

    return snap
