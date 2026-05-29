"""chimera.cli — jni cmd commands."""

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
@click.option("--ghidra-home", type=str, default=None)
def jni(path: str, project_dir: str | None, cache_dir: str | None,
        ghidra_home: str | None):
    """List JNI bindings (Java native methods + their bound native fns)."""
    asyncio.run(_jni_cmd(path, project_dir, cache_dir, ghidra_home))



async def _jni_cmd(path, project_dir, cache_dir, ghidra_home):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        natives = [
            f for f in model.functions
            if f.layer == "jvm" and f.metadata and f.metadata.get("is_native")
        ]
        click.echo(f"Native methods: {len(natives)}")
        for f in natives:
            callees = model.get_callees(f.address)
            target = callees[0].address if callees else "(unbound)"
            click.echo(f"  {f.metadata['class_fqcn']}.{f.name}{f.metadata['smali_sig']}  ->  {target}")
    finally:
        await engine.cleanup()
