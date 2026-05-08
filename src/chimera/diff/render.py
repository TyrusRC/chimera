"""Render a ProjectDiff to Markdown or JSON."""
from __future__ import annotations

from typing import Any

from chimera.diff.engine import NativeLibChange, ProjectDiff


def render_json(diff: ProjectDiff) -> dict[str, Any]:
    return {
        "a_sha256": diff.a_sha256,
        "b_sha256": diff.b_sha256,
        "permissions": {
            "added": list(diff.permissions_added),
            "removed": list(diff.permissions_removed),
        },
        "exported_components": {
            "added": [{"kind": c.kind, "name": c.name, "line": c.line}
                      for c in diff.exported_added],
            "removed": [{"kind": c.kind, "name": c.name, "line": c.line}
                        for c in diff.exported_removed],
        },
        "sdks": {
            "added": list(diff.sdks_added),
            "removed": list(diff.sdks_removed),
        },
        "native_libs": {
            "added": [_lib_dict(n) for n in diff.native_libs_added],
            "removed": [_lib_dict(n) for n in diff.native_libs_removed],
            "changed": [_lib_dict(n) for n in diff.native_libs_changed],
        },
        "findings": {
            "added": [f.to_dict() for f in diff.findings_added],
            "resolved": [f.to_dict() for f in diff.findings_resolved],
        },
    }


def _lib_dict(n: NativeLibChange) -> dict[str, Any]:
    return {"name": n.name, "a_sha256": n.a_sha256, "b_sha256": n.b_sha256}


def render_markdown(diff: ProjectDiff) -> str:
    """Render the diff as a human-readable Markdown report."""
    parts: list[str] = ["# chimera diff", "",
                        f"A: sha256:{diff.a_sha256}",
                        f"B: sha256:{diff.b_sha256}", ""]

    sections_added = 0

    if diff.permissions_added or diff.permissions_removed:
        sections_added += 1
        parts.append("## Permissions")
        for p in diff.permissions_added:
            parts.append(f"+ {p}")
        for p in diff.permissions_removed:
            parts.append(f"- {p}")
        parts.append("")

    if diff.exported_added or diff.exported_removed:
        sections_added += 1
        parts.append("## Exported components")
        for c in diff.exported_added:
            parts.append(f"+ {c.kind} {c.name}")
        for c in diff.exported_removed:
            parts.append(f"- {c.kind} {c.name}")
        parts.append("")

    if diff.sdks_added or diff.sdks_removed:
        sections_added += 1
        parts.append("## SDKs")
        for s in diff.sdks_added:
            parts.append(f"+ {s}")
        for s in diff.sdks_removed:
            parts.append(f"- {s}")
        parts.append("")

    if diff.native_libs_added or diff.native_libs_removed or diff.native_libs_changed:
        sections_added += 1
        parts.append("## Native libraries")
        for n in diff.native_libs_added:
            parts.append(f"+ {n.name} ({(n.b_sha256 or '?')[:12]})")
        for n in diff.native_libs_removed:
            parts.append(f"- {n.name} ({(n.a_sha256 or '?')[:12]})")
        for n in diff.native_libs_changed:
            a = (n.a_sha256 or '?')[:12]
            b = (n.b_sha256 or '?')[:12]
            parts.append(f"~ {n.name} ({a} → {b})")
        parts.append("")

    if diff.findings_added or diff.findings_resolved:
        sections_added += 1
        parts.append("## Findings")
        for f in diff.findings_added:
            ev = f.evidence[0] if f.evidence else ""
            parts.append(f"+ {f.finding_id} (regression) — {ev}")
        for f in diff.findings_resolved:
            ev = f.evidence[0] if f.evidence else ""
            parts.append(f"- {f.finding_id} (resolved) — {ev}")
        parts.append("")

    if sections_added == 0:
        parts.append("no differences detected")

    return "\n".join(parts)
