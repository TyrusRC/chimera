"""Compute the diff between two cached chimera projects."""
from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from chimera.detection_engineering.cvss_findings import Finding
from chimera.detection_engineering.manifest_findings import build_findings_from_models
from chimera.diff.loader import ProjectSnapshot
from chimera.parsers.android_manifest import (
    ManifestComponent, ManifestModel, parse_manifest,
)
from chimera.parsers.network_security_config import NSCModel, parse_nsc


@dataclass
class NativeLibChange:
    name: str
    a_sha256: Optional[str] = None
    b_sha256: Optional[str] = None


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
    native_libs_added: list[NativeLibChange] = field(default_factory=list)
    native_libs_removed: list[NativeLibChange] = field(default_factory=list)
    native_libs_changed: list[NativeLibChange] = field(default_factory=list)
    findings_added: list[Finding] = field(default_factory=list)
    findings_resolved: list[Finding] = field(default_factory=list)


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


def _parse_nsc_or_none(xml: Optional[bytes]) -> Optional[NSCModel]:
    if not xml:
        return None
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "network_security_config.xml"
        p.write_bytes(xml)
        try:
            return parse_nsc(p)
        except Exception:
            return None


_LINE_SUFFIX_RE = re.compile(r":(\d+)(\s|$)")


def _evidence_key(f: Finding) -> str:
    """Stable identity for a finding's evidence, independent of source-line shifts.

    Manifest/NSC evidence strings embed a ``:<line>`` suffix
    (e.g. ``AndroidManifest.xml:14 cleartextTraffic=true``). Any unrelated
    line shift would otherwise reclassify an unchanged finding as
    ``resolved + added``. Strip the line suffix so identity is anchored
    to (file, element) rather than (file, line).
    """
    if not f.evidence:
        return ""
    text = f.evidence[0]
    # Drop ":<line>" suffixes that appear in manifest/NSC evidence formats.
    return _LINE_SUFFIX_RE.sub(r"\2", text).strip()


def _findings_for(snap: ProjectSnapshot) -> list[Finding]:
    manifest = _parse_manifest_or_none(snap.manifest_xml)
    if manifest is None:
        return []
    nsc = _parse_nsc_or_none(snap.nsc_xml)
    return build_findings_from_models(manifest, nsc=nsc)


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

    a_libs = a.native_libs
    b_libs = b.native_libs
    for name in sorted(set(b_libs) - set(a_libs)):
        diff.native_libs_added.append(NativeLibChange(
            name=name, b_sha256=b_libs[name].get("sha256"),
        ))
    for name in sorted(set(a_libs) - set(b_libs)):
        diff.native_libs_removed.append(NativeLibChange(
            name=name, a_sha256=a_libs[name].get("sha256"),
        ))
    for name in sorted(set(a_libs) & set(b_libs)):
        a_sha = a_libs[name].get("sha256")
        b_sha = b_libs[name].get("sha256")
        if a_sha and b_sha and a_sha != b_sha:
            diff.native_libs_changed.append(NativeLibChange(
                name=name, a_sha256=a_sha, b_sha256=b_sha,
            ))

    a_findings = _findings_for(a)
    b_findings = _findings_for(b)
    a_keys = {(f.finding_id, _evidence_key(f)) for f in a_findings}
    b_keys = {(f.finding_id, _evidence_key(f)) for f in b_findings}
    diff.findings_added = [f for f in b_findings
                           if (f.finding_id, _evidence_key(f)) not in a_keys]
    diff.findings_resolved = [f for f in a_findings
                              if (f.finding_id, _evidence_key(f)) not in b_keys]

    return diff
