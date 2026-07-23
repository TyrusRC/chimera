"""Shared response parsers for AI-backed analyst workflows.

Centralising these here so the CLI surface (`chimera ai ...`) and the
HTTP surface (`/api/projects/{id}/ai/...`) parse the model's output the
same way. Previously each side carried its own copy, which is exactly
the kind of drift that produces "the API accepts this rename but the
CLI rejects it" bugs.
"""

from __future__ import annotations

import json
import re

_IDENT_SUB = re.compile(r"[^A-Za-z0-9_]")


def sanitize_symbol_name(name: str, *, max_len: int = 128) -> str | None:
    """Coerce a model-suggested symbol name into a safe C-style identifier.

    Decompiled bytes — including attacker-controlled strings/symbols in a
    malicious binary — flow verbatim into the rename prompt, so the model's
    output is untrusted at the point it would be written to the overlay. This
    is that trust boundary: keep only the first token, replace any non
    `[A-Za-z0-9_]` character, cap the length, and never let a name start with
    a digit. Returns None when nothing meaningful remains so the caller skips
    the rename rather than committing junk.
    """
    if not name:
        return None
    tokens = name.strip().split()
    if not tokens:
        return None
    s = _IDENT_SUB.sub("_", tokens[0])[:max_len]
    if not s:
        return None
    if s[0].isdigit():
        s = "_" + s[: max_len - 1]
    if not s.strip("_"):  # all-underscore names carry no meaning
        return None
    return s


def strip_fence(text: str) -> str:
    """Pull the body out of ```lang ... ``` fences the model may emit.

    Tolerant: leaves text unchanged if there's no opening fence, so it's
    safe to call unconditionally on any model output.
    """
    t = text.strip()
    if not t.startswith("```"):
        return t
    # Drop the opening ``` + optional language tag on the same line.
    first_nl = t.find("\n")
    if first_nl != -1:
        t = t[first_nl + 1 :]
    # Drop the closing fence if present.
    if t.endswith("```"):
        t = t[:-3].rstrip()
    return t


def parse_rename_json(raw: str) -> dict | None:
    """Parse the `{name, confidence}` payload SymGen-style prompts ask for.

    Tolerates code fences and apologetic prose by extracting the first
    {...} block when the model wraps its answer. Returns None when
    nothing parseable surfaces — callers prefer skipping a function
    over committing a hallucinated rename.
    """
    txt = strip_fence(raw)
    # Last-ditch: pull the first {..} substring if the model wrapped prose.
    if not txt.startswith("{"):
        lo = txt.find("{")
        hi = txt.rfind("}")
        if lo != -1 and hi != -1 and hi > lo:
            txt = txt[lo : hi + 1]
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        return None
    name = sanitize_symbol_name(str(data.get("name") or ""))
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    if not name:
        return None
    return {"name": name, "confidence": max(0.0, min(1.0, conf))}
