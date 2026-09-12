"""chimera.cli — yara cmd commands."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Write the rule to this file (default: stdout)")
@click.option("--family", type=str, default=None,
              help="Family/campaign tag for the rule's meta block")
@click.option("--name", "rule_name", type=str, default=None,
              help="Override the rule name (default: Chimera_<sha12>)")
@click.option("--max-strings", type=int, default=12)
@click.option("--max-imports", type=int, default=10)
@click.option("--min-string-length", type=int, default=8)
@click.option("--min-matches", type=int, default=4,
              help="Minimum number of strings/imports that must match")
def yara(path: str, project_dir: str | None, cache_dir: str | None,
         out_path: str | None, family: str | None, rule_name: str | None,
         max_strings: int, max_imports: int, min_string_length: int,
         min_matches: int):
    """Author a draft YARA rule from an analyzed binary.

    Runs the binary through `chimera analyze` (cache-warm reuse) and
    emits a YARA rule built from high-fitness strings + scored imports.
    The output is a *draft* — review and prune before deploying.
    """
    asyncio.run(_yara_cmd(
        path, project_dir, cache_dir, out_path, family, rule_name,
        max_strings, max_imports, min_string_length, min_matches,
    ))



@main.command("yara-solve")
@click.argument("rule", type=click.Path(exists=True, dir_okay=False))
@click.option("--size", type=int, default=None,
              help="File length in bytes (when the rule has no `filesize == N`).")
@click.option("--max-hash-len", type=int, default=3,
              help="Max window length to brute-force for hash.* atoms (default 3).")
@click.option("--binary", is_flag=True,
              help="Allow non-printable bytes (default assumes an ASCII flag).")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Write the solved file here.")
def yara_solve(rule: str, size: int | None, max_hash_len: int,
               binary: bool, out_path: str | None):
    """Synthesise a file that MATCHES a YARA rule (reverse a rule to its input).

    Translates the condition to a Z3 bit-vector model and brute-forces short
    hash windows — the YARA-keygen solver (recover the flag a rule accepts) and
    a rule-QA check. Needs the 'solve' extra (z3). Verifies with yara-python.
    """
    from chimera.detection_engineering.yara_solve import solve_yara_file, z3_available
    if not z3_available():
        raise click.ClickException('z3 not installed — pip install "chimera[solve]"')
    r = solve_yara_file(rule, size=size, max_hash_len=max_hash_len,
                        printable=not binary)
    if not r.get("sat"):
        click.echo(f"chimera yara-solve: {r.get('error') or r.get('note')}", err=True)
        if r.get("unsupported_atoms"):
            click.echo(f"  unsupported atoms: {r['unsupported_atoms'][:5]}", err=True)
        raise click.exceptions.Exit(1)
    click.echo(f"filesize={r['filesize']}  hash-windows-pinned={r['pinned_hash_windows']}  "
               f"yara-match={r['matched']}")
    if r.get("unsupported_atoms"):
        click.echo(f"  note: {len(r['unsupported_atoms'])} atom(s) unsupported and ignored")
    click.echo(f"  ascii: {r['ascii']!r}")
    click.echo(f"  hex:   {r['data_hex']}")
    if out_path:
        Path(out_path).write_bytes(bytes.fromhex(r["data_hex"]))
        click.echo(f"  wrote {out_path}")


async def _yara_cmd(path, project_dir, cache_dir, out_path, family,
                    rule_name, max_strings, max_imports, min_string_length,
                    min_matches):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.yara_author import author_yara_rule
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        rule = author_yara_rule(
            model,
            rule_name=rule_name,
            family=family,
            max_strings=max_strings,
            max_imports=max_imports,
            min_string_length=min_string_length,
            min_string_matches=min_matches,
        )
        if out_path:
            Path(out_path).write_text(rule, encoding="utf-8")
            click.echo(f"Wrote YARA rule to {out_path}")
        else:
            click.echo(rule)
    finally:
        await engine.cleanup()
