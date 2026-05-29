"""chimera.cli — info commands."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
def info():
    """Show Chimera version, available backends, and bundled rule counts."""
    from chimera.adapters.capa_adapter import CapaAdapter
    from chimera.adapters.ghidra import GhidraAdapter
    from chimera.adapters.jadx import JadxAdapter
    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.adapters.yara_adapter import YaraAdapter

    click.echo(f"Chimera v{__version__}")
    click.echo()
    click.echo("Backend status:")
    for adapter_cls in [Radare2Adapter, GhidraAdapter, JadxAdapter,
                        YaraAdapter, CapaAdapter]:
        adapter = adapter_cls()
        status = "available" if adapter.is_available() else "NOT FOUND"
        click.echo(f"  {adapter.name():12} {status}")

    # Surface what the rule-driven pieces actually have loaded so analysts
    # can tell at a glance whether the pipeline will detect anything.
    click.echo()
    click.echo("Rules / signatures loaded:")
    yara_count = _count_yara_rules()
    click.echo(f"  YARA rules:           {yara_count}")
    sdk_count = _count_sdk_signatures()
    click.echo(f"  SDK signatures:       {sdk_count}")
    semgrep_dir = _semgrep_rules_dir()
    if semgrep_dir is not None:
        click.echo(f"  Semgrep rules dir:    {semgrep_dir}")



def _count_yara_rules() -> int:
    rules_dir = Path(__file__).resolve().parent / "bypass" / "yara_rules"
    if not rules_dir.exists():
        return 0
    total = 0
    for path in rules_dir.glob("*.yar"):
        try:
            total += sum(
                1 for line in path.read_text().splitlines()
                if line.strip().startswith("rule ")
            )
        except OSError:
            continue
    return total



def _count_sdk_signatures() -> int:
    try:
        from chimera.sdk.signatures import SDK_SIGNATURES
    except ImportError:
        return 0
    return len(SDK_SIGNATURES)



def _semgrep_rules_dir() -> Path | None:
    """Best-effort discovery of a bundled or env-provided Semgrep rule dir."""
    import os
    env = os.environ.get("CHIMERA_SEMGREP_RULES")
    if env and Path(env).exists():
        return Path(env)
    # Some installs bundle rules at /opt/chimera/semgrep_rules.
    bundled = Path("/opt/chimera/semgrep_rules")
    if bundled.exists():
        return bundled
    return None
