"""`chimera install` — auto-wire chimera into every present agent host.

Fully automatic (no prompt): detect installed hosts, back up each config,
merge chimera's MCP entry idempotently, print what changed. Safe by
construction — backups + never clobbering other entries.
"""
from __future__ import annotations

import json

import click

from chimera.cli._root import main
from chimera.integrations import build_registry
from chimera.integrations.base import backup
from chimera.integrations.command import build_launch_command


@main.command("install")
@click.option("--dry-run", is_flag=True, help="Show what would change; write nothing.")
@click.option("--host", "hosts", multiple=True, help="Restrict to named host(s).")
@click.option("--all", "all_hosts", is_flag=True, help="Write every known host, even if not detected.")
@click.option("--portable", is_flag=True, help="Use the uvx (no-clone) launch command.")
@click.option("--status", is_flag=True, help="Report which hosts are wired; write nothing.")
@click.option("--uninstall", is_flag=True, help="Remove chimera's entry from detected hosts.")
def install(dry_run, hosts, all_hosts, portable, status, uninstall):
    registry = build_registry()
    if hosts:
        unknown = [h for h in hosts if h not in registry]
        if unknown:
            raise click.BadParameter(f"unknown host(s): {', '.join(unknown)}")
        selected = [registry[h] for h in hosts]
    else:
        selected = list(registry.values())

    if status:
        for h in selected:
            state = "wired  " if h.is_wired() else "absent "
            click.echo(f"{state} {h.name}: {h.target_path()}")
        return

    if uninstall:
        raise SystemExit(_run_uninstall(selected, dry_run))

    entry = build_launch_command(portable=portable)
    targets = selected if (hosts or all_hosts) else [h for h in selected if h.detect()]

    failures = []
    for h in targets:
        try:
            summary = h.apply(entry, dry_run=dry_run)
        except (json.JSONDecodeError, ValueError, OSError) as e:
            # spec: back up the unparseable file, do not write, fail this host only.
            try:
                p = h.target_path()
                if not dry_run and p.exists():
                    backup(p)
            except OSError:
                pass
            failures.append(f"{h.name}: {e}")
            continue
        if summary:
            click.echo(("would write " if dry_run else "wrote ") + summary)
        else:
            click.echo(f"unchanged {h.name}")

    for f in failures:
        click.echo(f"FAILED {f}", err=True)
    if failures:
        raise SystemExit(1)


def _run_uninstall(selected, dry_run) -> int:
    for h in selected:
        remover = getattr(h, "remove", None)
        if remover is None:
            click.echo(f"skip {h.name}: uninstall not supported")
            continue
        if remover(dry_run=dry_run):
            click.echo(f"removed {h.name}")
        else:
            click.echo(f"unchanged {h.name}")
    return 0
