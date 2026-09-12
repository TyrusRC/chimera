"""chimera yara-scan / capabilities / floss — on-demand malware-triage runs.

Thin CLI over chimera's existing adapters: scan a file with YARA (bundled +
optional extra rules), detect capa capabilities (ATT&CK/MBC), and recover
FLOSS stack/tight/decoded strings. Each degrades cleanly if its backend is
absent. (The existing `chimera yara` command AUTHORS a rule; this scans with one.)
"""
from __future__ import annotations

import asyncio
import json as _json
from pathlib import Path

import click

from chimera.cli._root import main


@main.command("yara-scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("-r", "--rules-dir", "rules_dir", type=click.Path(exists=True), default=None,
              help="Directory of extra .yar/.yara rules (added to the bundled set).")
@click.option("--json", "as_json", is_flag=True)
def yara_scan_cmd(target: str, rules_dir: str | None, as_json: bool):
    """Scan TARGET against the bundled (+ optional extra) YARA rules."""
    from chimera.adapters.yara_adapter import YaraAdapter
    a = YaraAdapter(extra_rules_dir=Path(rules_dir) if rules_dir else None)
    if not a.is_available():
        raise click.ClickException("yara-python not installed — pip install yara-python")
    r = asyncio.run(a.analyze(target, {}))
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    hits = r.get("hits", [])
    click.echo(f"[chimera] yara-scan: {len(hits)} hit(s)")
    for h in hits:
        tags = f" [{', '.join(h.get('tags', []))}]" if h.get("tags") else ""
        click.echo(f"  {h['rule']}{tags}")


@main.command("capabilities")
@click.argument("target", type=click.Path(exists=True))
@click.option("-r", "--rules", "rules_dir", type=click.Path(exists=True), default=None,
              help="Custom capa rules directory.")
@click.option("--backend", default=None, help="capa static backend (vivisect|pyghidra|binja|ida).")
@click.option("--json", "as_json", is_flag=True)
def capabilities_cmd(target: str, rules_dir: str | None, backend: str | None, as_json: bool):
    """Detect capabilities (capa → ATT&CK/MBC) in TARGET."""
    from chimera.adapters.capa_adapter import CapaAdapter
    a = CapaAdapter(rules_dir=rules_dir)
    if not a.is_available():
        raise click.ClickException('capa not found — pip install flare-capa')
    r = asyncio.run(a.analyze(target, {"backend": backend}))
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    caps = [c for c in r.get("capabilities", []) if not c.get("is_library")]
    click.echo(f"[chimera] capa: {len(caps)} capabilities")
    for c in caps[:60]:
        atk = f"  ATT&CK={','.join(c['attack'])}" if c.get("attack") else ""
        click.echo(f"  {c['namespace']}: {c['rule']}{atk}")
    if r.get("error"):
        click.echo(f"  note: {r['error'][:200]}")


@main.command("floss")
@click.argument("target", type=click.Path(exists=True))
@click.option("--timeout", type=int, default=90)
@click.option("--json", "as_json", is_flag=True)
def floss_cmd(target: str, timeout: int, as_json: bool):
    """Recover stack/tight/decoded strings (FLOSS) from TARGET."""
    from chimera.adapters.floss import FlossAdapter
    a = FlossAdapter()
    if not a.is_available():
        raise click.ClickException('floss not found — pip install flare-floss')
    r = asyncio.run(a.analyze(target, {"timeout": timeout}))
    if as_json:
        click.echo(_json.dumps(r, indent=2)); return
    st = r.get("stats", {})
    click.echo(f"[chimera] floss: decoded={st.get('decoded_count', 0)} "
               f"stack={st.get('stack_count', 0)} tight={st.get('tight_count', 0)}")
    for label, key in (("decoded", "decoded"), ("stack", "stack"), ("tight", "tight")):
        for s in r.get(key, [])[:40]:
            click.echo(f"  [{label}] {s.get('value')}")
    if r.get("error"):
        click.echo(f"  note: {r['error'][:200]}")
