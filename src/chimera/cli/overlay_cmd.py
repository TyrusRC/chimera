"""chimera.cli — overlay cmd commands."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# overlay — export/import analyst annotations (for sharing across analysts)
# ----------------------------------------------------------------------


@main.group()
def overlay():
    """Export / import the analyst annotation overlay (renames, comments, types)."""



@overlay.command("export")
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("-o", "--out", "out_path", type=click.Path(), default=None,
              help="Output file (default: stdout).")
def overlay_export(path: str, project_dir: str | None, out_path: str | None):
    """Export the overlay for the binary at PATH as a portable JSON document."""
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay
    from chimera.model.binary import BinaryInfo
    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    cfg = ChimeraConfig(**kwargs)
    b = BinaryInfo.from_path(Path(path))
    overlay = ProjectOverlay.load(cfg.project_dir, b.sha256)
    payload = {
        "schema": "chimera-overlay-export/1",
        "sha256": b.sha256,
        "source_path": str(Path(path).name),
        "function_names": overlay.function_names,
        "variable_renames": overlay.variable_renames,
        "comments": overlay.comments,
        "function_types": overlay.function_types,
        "user_classifications": overlay.user_classifications,
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out_path:
        Path(out_path).write_text(text)
        click.echo(f"[chimera] overlay exported → {out_path}")
    else:
        click.echo(text)



@overlay.command("import")
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("-i", "--in", "in_path", type=click.Path(exists=True), required=True,
              help="Input overlay JSON.")
@click.option("--mode", type=click.Choice(["merge", "replace"]), default="merge",
              help="merge: overlay-on-top; replace: discard local overlay first.")
def overlay_import(path: str, project_dir: str | None, in_path: str, mode: str):
    """Import an overlay JSON into the project for the binary at PATH."""
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay
    from chimera.model.binary import BinaryInfo

    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    cfg = ChimeraConfig(**kwargs)
    b = BinaryInfo.from_path(Path(path))
    incoming = json.loads(Path(in_path).read_text())
    incoming_sha = incoming.get("sha256", "")
    if incoming_sha and incoming_sha != b.sha256:
        click.echo(
            f"[chimera] WARN: overlay was exported from a different binary "
            f"(sha={incoming_sha[:12]}… vs current {b.sha256[:12]}…). "
            "Addresses may not line up.",
            err=True,
        )
    target = ProjectOverlay.load(cfg.project_dir, b.sha256)
    if mode == "replace":
        target.function_names.clear()
        target.variable_renames.clear()
        target.comments.clear()
        target.function_types.clear()
        target.user_classifications.clear()
    # Merge: incoming values win on conflict.
    target.function_names.update(incoming.get("function_names") or {})
    for addr, vmap in (incoming.get("variable_renames") or {}).items():
        target.variable_renames.setdefault(addr, {}).update(vmap)
    for addr, cmap in (incoming.get("comments") or {}).items():
        target.comments.setdefault(addr, {}).update(cmap)
    target.function_types.update(incoming.get("function_types") or {})
    target.user_classifications.update(incoming.get("user_classifications") or {})
    target.save()
    click.echo(
        f"[chimera] overlay imported ({mode}): "
        f"{len(target.function_names)} renames, "
        f"{len(target.comments)} commented addrs, "
        f"{len(target.function_types)} typed"
    )


# ----------------------------------------------------------------------
# overlay propagate — carry annotations from an old build to a new one
# ----------------------------------------------------------------------


@overlay.command("propagate")
@click.argument("old", type=click.Path(exists=True))
@click.argument("new", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--threshold", type=float, default=0.85,
              help="Minimum function similarity to carry an annotation.")
@click.option("--heuristic", type=click.Choice(["jaccard", "multi"]), default="jaccard")
@click.option("--apply/--preview", default=False,
              help="Write carried annotations into NEW's overlay (default: preview).")
def overlay_propagate(old: str, new: str, project_dir: str | None,
                      threshold: float, heuristic: str, apply: bool):
    """Move renames/comments/types from OLD's overlay onto NEW via similarity.

    A rebuild shifts every address; this matches OLD→NEW functions with
    `diff-functions` and carries each annotation onto its matched twin.
    Only matches at or above --threshold carry; the rest are reported so
    nothing is lost silently. Preview by default; --apply persists.
    """
    import asyncio

    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.core.overlay import ProjectOverlay
    from chimera.diff.function_similarity import diff_models
    from chimera.diff.overlay_propagate import apply_plan, build_plan

    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    cfg = ChimeraConfig(**kwargs)

    async def _run():
        engine = ChimeraEngine(cfg)
        return await engine.analyze(old), await engine.analyze(new)
    ma, mb = asyncio.run(_run())

    overlay_a = ProjectOverlay.load(cfg.project_dir, ma.binary.sha256)
    result = diff_models(ma, mb, threshold=threshold, heuristic=heuristic)
    plan = build_plan(overlay_a, result["matched"], min_similarity=threshold)
    s = plan.summary()

    click.echo(f"[chimera] propagate {Path(old).name} → {Path(new).name}")
    click.echo(f"  carried:             {s['carried']}")
    click.echo(f"  skipped (drifted):   {s['skipped_low_similarity']}")
    click.echo(f"  skipped (unmatched): {s['skipped_unmatched']}")
    for c in plan.carried[:20]:
        click.echo(f"    ~ {c.a_address} → {c.b_address}  "
                   f"{c.name!r}  sim={c.similarity:.2f}")
    for sk in plan.skipped_unmatched[:20]:
        click.echo(f"    ? {sk['a_address']} annotated in OLD, no match in NEW")

    if not apply:
        click.echo("[chimera] preview only — re-run with --apply to write NEW's overlay.")
        return
    overlay_b = ProjectOverlay.load(cfg.project_dir, mb.binary.sha256)
    apply_plan(plan, overlay_b)
    overlay_b.save()
    click.echo(f"[chimera] applied {s['carried']} function annotations to "
               f"{Path(new).name}'s overlay.")
