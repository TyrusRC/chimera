"""Write-back tools — let the driving LLM persist its findings.

Every other handler group reads the loaded model; this one writes. An
analyst (human or model) renames a function, comments an address, pins a
type signature or a classification, or records a narrative note, and the
change lands in the same per-binary ``overlay.json`` the HTTP API and CLI
already use — atomic tempfile + rename, applied to the live model so the
next `get_function` reflects it, and surviving restart.

Without these tools the MCP surface is read-only: a model can locate the
key-check in a crackme but cannot record what it found. That is the gap
this closes. The backend (`ProjectOverlay`) is unchanged — this is wiring.

Returns None for a tool it does not own, so the server tries the next group.
"""
from __future__ import annotations

import logging

from mcp.types import TextContent

from chimera import mcp_session as mcpstate
from chimera.core.addr import normalize_address
from chimera.core.overlay import ProjectOverlay

logger = logging.getLogger(__name__)

_WRITE_TOOLS = frozenset({
    "rename_function", "set_comment", "set_function_type",
    "set_classification", "add_note", "list_annotations", "batch_annotate",
})


def _load_overlay():
    """(overlay, model) for the loaded binary, or (None, None) if none loaded."""
    model = mcpstate.current_model
    if model is None:
        return None, None
    engine = mcpstate.get_engine()
    overlay = ProjectOverlay.load(engine.config.project_dir, model.binary.sha256)
    return overlay, model


def _apply_op(overlay: ProjectOverlay, model, op: dict) -> dict:
    """Apply one annotation op to overlay + live model. Returns a result row.

    Does not save — the caller saves once so a batch is a single atomic
    write. Unknown ops and missing fields produce an error row rather than
    raising, so one bad entry in a batch does not sink the rest.
    """
    kind = op.get("op")
    addr_raw = op.get("address")
    if kind in {"rename", "comment", "type", "classify", "rename_variable"} and not addr_raw:
        return {"op": kind, "ok": False, "error": "missing 'address'"}
    addr = normalize_address(addr_raw) if addr_raw else None
    func = model.get_function(addr) if addr else None

    if kind == "rename":
        name = op.get("name")
        if not name:
            return {"op": kind, "ok": False, "address": addr, "error": "missing 'name'"}
        overlay.rename_function(addr, name)
        if func is not None:
            func.name = name
        return {"op": kind, "ok": True, "address": addr, "name": name,
                "model_updated": func is not None}

    if kind == "rename_variable":
        original, new = op.get("original"), op.get("new_name")
        if not original or not new:
            return {"op": kind, "ok": False, "address": addr,
                    "error": "requires 'original' and 'new_name'"}
        overlay.rename_variable(addr, original, new)
        return {"op": kind, "ok": True, "address": addr,
                "original": original, "new_name": new}

    if kind == "comment":
        text = op.get("text")
        if text is None:
            return {"op": kind, "ok": False, "address": addr, "error": "missing 'text'"}
        line = op.get("line", 0)
        overlay.add_comment(addr, line, text)
        return {"op": kind, "ok": True, "address": addr, "line": line}

    if kind == "type":
        sig = op.get("signature")
        if not sig:
            return {"op": kind, "ok": False, "address": addr, "error": "missing 'signature'"}
        overlay.set_function_type(addr, sig)
        if func is not None:
            func.signature = sig
        return {"op": kind, "ok": True, "address": addr, "signature": sig,
                "model_updated": func is not None}

    if kind == "classify":
        cls = op.get("classification")
        if not cls:
            return {"op": kind, "ok": False, "address": addr, "error": "missing 'classification'"}
        overlay.set_classification(addr, cls)
        if func is not None:
            func.classification = cls
        return {"op": kind, "ok": True, "address": addr, "classification": cls,
                "model_updated": func is not None}

    return {"op": kind, "ok": False, "error": f"unknown op: {kind!r}"}


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    if name not in _WRITE_TOOLS:
        return None

    overlay, model = _load_overlay()
    if overlay is None:
        return mcpstate.error("No analysis loaded. Call analyze(path=...) first.")

    if name == "list_annotations":
        return mcpstate.json_reply({
            "sha256": model.binary.sha256[:16],
            "function_names": overlay.function_names,
            "variable_renames": overlay.variable_renames,
            "comments": overlay.comments,
            "function_types": overlay.function_types,
            "user_classifications": overlay.user_classifications,
            "notes": overlay.list_notes(),
        })

    if name == "add_note":
        title = arguments.get("title")
        if not title:
            return mcpstate.error("add_note requires 'title'.")
        note_id = overlay.add_note(
            title=title,
            body=arguments.get("body", ""),
            tags=arguments.get("tags"),
            evidence=arguments.get("evidence"),
        )
        overlay.save()
        return mcpstate.json_reply({"ok": True, "note_id": note_id})

    if name == "batch_annotate":
        ops = arguments.get("ops") or []
        if not isinstance(ops, list):
            return mcpstate.error("'ops' must be a list of annotation operations.")
        results = [_apply_op(overlay, model, op if isinstance(op, dict) else {})
                   for op in ops]
        overlay.save()
        applied = sum(1 for r in results if r.get("ok"))
        return mcpstate.json_reply({"ok": True, "applied": applied,
                                    "total": len(results), "results": results})

    # Single-edit tools map onto the same op applier, then save once.
    op = {
        "rename_function": {"op": "rename", "address": arguments.get("address"),
                            "name": arguments.get("name")},
        "set_comment": {"op": "comment", "address": arguments.get("address"),
                        "text": arguments.get("text"), "line": arguments.get("line", 0)},
        "set_function_type": {"op": "type", "address": arguments.get("address"),
                              "signature": arguments.get("signature")},
        "set_classification": {"op": "classify", "address": arguments.get("address"),
                               "classification": arguments.get("classification")},
    }[name]
    result = _apply_op(overlay, model, op)
    if result.get("ok"):
        overlay.save()
    return mcpstate.json_reply(result)
