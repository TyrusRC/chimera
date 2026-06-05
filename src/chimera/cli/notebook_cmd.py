"""chimera.cli — notebook (narrative findings) commands.

Notebook entries are stored alongside the analyst overlay so they travel
with the project. The CLI surface mirrors the API: list / add / remove,
keyed by sha256 of the binary on disk.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


def _load_overlay(path: str, project_dir: str | None):
    """Resolve overlay for the binary at PATH; common to every notes command."""
    from chimera.core.config import ChimeraConfig
    from chimera.core.overlay import ProjectOverlay
    from chimera.model.binary import BinaryInfo

    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    cfg = ChimeraConfig(**kwargs)
    b = BinaryInfo.from_path(Path(path))
    return ProjectOverlay.load(cfg.project_dir, b.sha256)


@main.group()
def notes():
    """Manage notebook entries (narrative findings with evidence)."""


@notes.command("list")
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--tag", default=None, help="Filter by tag.")
def notes_list(path: str, project_dir: str | None, tag: str | None):
    """List notebook entries for the binary at PATH."""
    overlay = _load_overlay(path, project_dir)
    entries = overlay.list_notes(tag=tag)
    if not entries:
        click.echo("[chimera] no notes")
        return
    for e in entries:
        tags = ",".join(e.get("tags") or [])
        ev = len(e.get("evidence") or [])
        click.echo(
            f"{e['id'][:8]}  {e['title']}"
            f"  [tags={tags or '-'}, evidence={ev}]"
        )


@notes.command("add")
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--title", required=True, help="Note title.")
@click.option("--body", default="", help="Note body (markdown ok).")
@click.option("--tag", "tags", multiple=True, help="Tag (repeatable).")
@click.option("--evidence", "evidence", multiple=True,
              help="Address to link as evidence (repeatable, e.g. 0x140001000).")
def notes_add(
    path: str,
    project_dir: str | None,
    title: str,
    body: str,
    tags: tuple[str, ...],
    evidence: tuple[str, ...],
):
    """Add a notebook entry for the binary at PATH."""
    overlay = _load_overlay(path, project_dir)
    ev_payload = [{"address": a, "line": 0} for a in evidence]
    note_id = overlay.add_note(
        title=title,
        body=body,
        tags=list(tags) or None,
        evidence=ev_payload or None,
    )
    overlay.save()
    click.echo(f"[chimera] note added: {note_id}")


@notes.command("rm")
@click.argument("path", type=click.Path(exists=True))
@click.argument("note_id")
@click.option("--project-dir", type=click.Path(), default=None)
def notes_rm(path: str, note_id: str, project_dir: str | None):
    """Remove a notebook entry by id."""
    overlay = _load_overlay(path, project_dir)
    # Allow prefix match for convenience — `chimera notes list` shows 8-char prefixes.
    if note_id not in overlay.notes:
        candidates = [k for k in overlay.notes if k.startswith(note_id)]
        if len(candidates) == 1:
            note_id = candidates[0]
        elif len(candidates) > 1:
            click.echo(f"[chimera] ambiguous prefix '{note_id}' "
                       f"matches {len(candidates)} notes", err=True)
            raise SystemExit(2)
    if not overlay.remove_note(note_id):
        click.echo(f"[chimera] no such note: {note_id}", err=True)
        raise SystemExit(1)
    overlay.save()
    click.echo(f"[chimera] note removed: {note_id}")
