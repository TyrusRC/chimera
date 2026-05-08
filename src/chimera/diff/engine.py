"""Compute the diff between two cached chimera projects."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from chimera.diff.loader import ProjectSnapshot
from chimera.parsers.android_manifest import (
    ManifestComponent, ManifestModel, parse_manifest,
)


@dataclass
class ProjectDiff:
    a_sha256: str
    b_sha256: str
    permissions_added: list[str] = field(default_factory=list)
    permissions_removed: list[str] = field(default_factory=list)
    exported_added: list[ManifestComponent] = field(default_factory=list)
    exported_removed: list[ManifestComponent] = field(default_factory=list)
    sdks_added: list[str] = field(default_factory=list)
    sdks_removed: list[str] = field(default_factory=list)


def _parse_manifest_or_none(xml: Optional[bytes]) -> Optional[ManifestModel]:
    if not xml:
        return None
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "AndroidManifest.xml"
        p.write_bytes(xml)
        try:
            return parse_manifest(p)
        except Exception:
            return None


def _exported_components(model: Optional[ManifestModel]) -> list[ManifestComponent]:
    if model is None:
        return []
    out: list[ManifestComponent] = []
    for comp in (model.activities + model.services
                 + model.receivers + model.providers):
        explicit = comp.exported is True
        implicit = comp.exported is None and comp.has_intent_filter
        if explicit or implicit:
            out.append(comp)
    return out


def diff_projects(a: ProjectSnapshot, b: ProjectSnapshot) -> ProjectDiff:
    """Pure function: compute the diff between two snapshots.

    Each dimension is best-effort. If a snapshot is missing data for a
    dimension (e.g. non-Android binary has no manifest), the corresponding
    diff fields are left empty.
    """
    diff = ProjectDiff(a_sha256=a.sha256, b_sha256=b.sha256)

    a_manifest = _parse_manifest_or_none(a.manifest_xml)
    b_manifest = _parse_manifest_or_none(b.manifest_xml)

    a_perms = set(a_manifest.permissions) if a_manifest else set()
    b_perms = set(b_manifest.permissions) if b_manifest else set()
    diff.permissions_added = sorted(b_perms - a_perms)
    diff.permissions_removed = sorted(a_perms - b_perms)

    a_exp = {(c.kind, c.name): c for c in _exported_components(a_manifest)}
    b_exp = {(c.kind, c.name): c for c in _exported_components(b_manifest)}
    diff.exported_added = [b_exp[k] for k in b_exp if k not in a_exp]
    diff.exported_removed = [a_exp[k] for k in a_exp if k not in b_exp]

    a_pkgs = set(a.jadx_packages)
    b_pkgs = set(b.jadx_packages)
    diff.sdks_added = sorted(b_pkgs - a_pkgs)
    diff.sdks_removed = sorted(a_pkgs - b_pkgs)

    return diff
