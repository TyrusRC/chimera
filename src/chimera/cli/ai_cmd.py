"""chimera.cli — ai cmd commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera.ai import parse_rename_json
from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# ai — LLM-assisted analyst helpers (explain, suggest name, suggest comment)
# ----------------------------------------------------------------------


@main.group()
def ai():
    """LLM-backed analyst helpers — explain, rename, comment.

    Requires ANTHROPIC_API_KEY in the environment. Override the model with
    CHIMERA_AI_MODEL (default: claude-sonnet-4-6).
    """



def _ai_decompile(path: str, address: str, project_dir: str | None,
                  cache_dir: str | None, backend: str) -> tuple[str, str]:
    """Run the chosen decompiler against `address` and return (code, name)."""
    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.core.overlay import ProjectOverlay
    from chimera.report.decomp_postprocess import post_process

    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    if cache_dir:
        kwargs["cache_dir"] = Path(cache_dir)
    cfg = ChimeraConfig(**kwargs)
    engine = ChimeraEngine(cfg)
    model = asyncio.run(engine.analyze(path))
    overlay = ProjectOverlay.load(cfg.project_dir, model.binary.sha256)
    func = model.get_function(address)
    if func is None:
        raise click.ClickException(f"function {address} not found in model")
    if backend == "ghidra" and func.decompiled:
        pp = post_process(func.decompiled, model, address, overlay=overlay)
        return pp.code, func.name
    r2 = Radare2Adapter()
    if not r2.is_available():
        raise click.ClickException("r2 is not installed; cannot decompile via r2")
    import r2pipe
    pipe = r2pipe.open(str(path), flags=["-2"])
    try:
        raw = r2._decompile_one(pipe, {"address": address})
    finally:
        pipe.quit()
    if not raw.get("ok"):
        raise click.ClickException(f"r2 decompile failed: {raw.get('error')}")
    pp = post_process(raw["code"], model, address, overlay=overlay)
    return pp.code, func.name



def _ai_call(fn, *args, **kwargs):
    from chimera.ai import AIError, AINotConfigured, default_client
    try:
        client = default_client()
    except AINotConfigured as exc:
        raise click.ClickException(str(exc))
    sys_p, user_p = fn(*args, **kwargs)
    try:
        return client.complete(sys_p, user_p)
    except AIError as exc:
        raise click.ClickException(str(exc))



@ai.command("explain")
@click.argument("path", type=click.Path(exists=True))
@click.argument("address", type=str)
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="r2",
              help="Decompiler backend to source the code from.")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def ai_explain(path: str, address: str, backend: str,
               project_dir: str | None, cache_dir: str | None):
    """Explain what the function at ADDRESS does."""
    from chimera.ai import explain_prompt
    code, name = _ai_decompile(path, address, project_dir, cache_dir, backend)
    text = _ai_call(explain_prompt, code, function_name=name, address=address)
    click.echo(text)



@ai.command("rename")
@click.argument("path", type=click.Path(exists=True))
@click.argument("address", type=str)
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="r2")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def ai_rename(path: str, address: str, backend: str,
              project_dir: str | None, cache_dir: str | None):
    """Suggest a snake_case name for the function at ADDRESS."""
    from chimera.ai import rename_prompt
    code, name = _ai_decompile(path, address, project_dir, cache_dir, backend)
    text = _ai_call(rename_prompt, code, current_name=name)
    click.echo(text.strip().splitlines()[0].strip().strip("`'\""))



@ai.command("comment")
@click.argument("path", type=click.Path(exists=True))
@click.argument("address", type=str)
@click.option("--line", type=int, default=0, help="Line number (0 = function header).")
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="r2")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def ai_comment(path: str, address: str, line: int, backend: str,
               project_dir: str | None, cache_dir: str | None):
    """Suggest a one-line comment for ADDRESS (optionally a specific line)."""
    from chimera.ai import comment_prompt
    code, _name = _ai_decompile(path, address, project_dir, cache_dir, backend)
    text = _ai_call(comment_prompt, code, line=line)
    click.echo(text.strip())



@ai.command("refine-decomp")
@click.argument("path", type=click.Path(exists=True))
@click.argument("address", type=str)
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="ghidra",
              help="Decompiler whose output should be refined (default: ghidra).")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def ai_refine_decomp(path: str, address: str, backend: str,
                     project_dir: str | None, cache_dir: str | None):
    """LLM4Decompile-V2-style refinement of decompiler output.

    Reads the chosen decompiler's output for ADDRESS, asks the LLM to
    rename placeholders and tighten control flow without changing
    semantics, and prints the refined C. Strictly preview — does not
    write to the overlay.
    """
    from chimera.ai import refine_decomp_prompt, strip_fence
    code, name = _ai_decompile(path, address, project_dir, cache_dir, backend)
    text = _ai_call(refine_decomp_prompt, code,
                    function_name=name, address=address)
    click.echo(strip_fence(text))



@ai.command("batch-rename")
@click.argument("path", type=click.Path(exists=True))
@click.option("--max", "max_functions", type=int, default=50,
              help="Maximum functions to consider in this pass.")
@click.option("--threshold", "min_confidence", type=float, default=0.7,
              help="Minimum confidence to auto-apply a name (when --apply).")
@click.option("--backend", type=click.Choice(["r2", "ghidra"]), default="r2")
@click.option("--apply/--preview", default=False,
              help="Apply suggestions to the overlay (default: preview-only).")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]),
              default="text")
def ai_batch_rename(path: str, max_functions: int, min_confidence: float,
                    backend: str, apply: bool,
                    project_dir: str | None, cache_dir: str | None,
                    fmt: str):
    """SymGen-style batch generative function naming.

    Walks the project's stripped-looking functions (FUN_/sub_/fn_), feeds
    callers/callees as context, and asks the LLM for a snake_case name +
    confidence. With --apply, high-confidence names are written to the
    overlay; otherwise this is a preview.
    """
    from chimera.ai import (
        AIError,
        AINotConfigured,
        batch_rename_prompt,
        default_client,
    )
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.core.overlay import ProjectOverlay

    try:
        client = default_client()
    except AINotConfigured as exc:
        raise click.ClickException(str(exc))

    kwargs: dict = {}
    if project_dir:
        kwargs["project_dir"] = Path(project_dir)
    if cache_dir:
        kwargs["cache_dir"] = Path(cache_dir)
    cfg = ChimeraConfig(**kwargs)
    engine = ChimeraEngine(cfg)
    model = asyncio.run(engine.analyze(path))
    overlay = ProjectOverlay.load(cfg.project_dir, model.binary.sha256)

    placeholder_prefixes = ("fun_", "sub_", "fn_", "func_", "loc_", "j_")
    candidates = []
    for f in model.functions:
        name = (f.name or "").lower()
        is_stripped = any(name.startswith(p) for p in placeholder_prefixes) or not name
        if not is_stripped:
            continue
        if f.address in overlay.function_names:
            continue
        if not f.decompiled and not (f.disassembly and len(f.disassembly) > 4):
            continue
        candidates.append(f)
    candidates.sort(key=lambda f: -len(model.get_callers(f.address) or []))
    candidates = candidates[:max_functions]

    if not candidates:
        click.echo("[chimera] no stripped-looking functions to rename")
        return

    suggestions = []
    for f in candidates:
        code = f.decompiled or ""
        if not code.strip():
            continue
        callers = [c.name for c in (model.get_callers(f.address) or []) if c.name][:6]
        callees = [c.name for c in (model.get_callees(f.address) or []) if c.name][:6]
        sys_p, user_p = batch_rename_prompt(
            code, current_name=f.name, callers=callers, callees=callees,
        )
        try:
            raw = client.complete(sys_p, user_p, max_tokens=160)
        except AIError as exc:
            click.echo(f"[chimera] WARN: model call failed for {f.address}: {exc}",
                       err=True)
            continue
        parsed = parse_rename_json(raw)
        if not parsed:
            continue
        applied = False
        if apply and parsed["confidence"] >= min_confidence:
            overlay.rename_function(f.address, parsed["name"])
            f.name = parsed["name"]
            applied = True
        suggestions.append({
            "address": f.address,
            "current_name": f.name if not applied else f.original_name,
            "suggested_name": parsed["name"],
            "confidence": parsed["confidence"],
            "applied": applied,
        })
    if apply:
        overlay.save()

    if fmt == "json":
        click.echo(json.dumps({"suggestions": suggestions}, indent=2))
        return
    click.echo(f"[chimera] batch-rename: {len(suggestions)} suggestions, "
               f"{sum(1 for s in suggestions if s['applied'])} applied")
    for s in suggestions:
        marker = "✓" if s["applied"] else " "
        click.echo(
            f"  {marker} {s['address']}  {s['current_name']!r} "
            f"→ {s['suggested_name']!r}  conf={s['confidence']:.2f}"
        )



# Backwards-compat re-export for the test suite, which imports
# `_parse_rename_json` from `chimera.cli`. The real implementation lives
# in `chimera.ai.parsing.parse_rename_json` so the API and CLI share one
# parser instead of drifting copies.
def _parse_rename_json(raw: str) -> dict | None:
    return parse_rename_json(raw)
