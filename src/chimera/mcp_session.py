"""Session state and reply helpers shared by the MCP tool handlers.

An MCP stdio server is a single long-lived conversation: one binary is
loaded by `analyze`, and every query tool afterwards reads that same
model. That state has to be reachable from each handler module, so it
lives here rather than as globals in one of them.

Handlers mutate it through this module's attributes
(``session.current_model = model``) rather than importing the names
directly — a ``from ... import current_model`` would bind a copy of the
reference and later writes would not be seen by anyone else.
"""
from __future__ import annotations

import json
import logging

from mcp.types import TextContent

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine

logger = logging.getLogger(__name__)

#: Lazily constructed on first use — building an engine costs adapter
#: registration, which a client that only ever calls `status` should not pay.
engine: ChimeraEngine | None = None

#: The binary currently loaded by `analyze`, or None.
current_model = None

#: What the last analysis actually ran: backends used, paths, options.
analysis_config: dict = {}


def get_engine() -> ChimeraEngine:
    global engine
    if engine is None:
        engine = ChimeraEngine(ChimeraConfig())
    return engine


def json_reply(data) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2))]


def error(msg: str) -> list[TextContent]:
    return json_reply({"error": msg})


def require_model() -> bool:
    return current_model is not None


async def raw_disasm_at(address: str, count: int = 64) -> dict | None:
    """Disassemble at a raw address via radare2, bypassing the function map.

    The discovered-function map only holds addresses r2 turned into named
    functions, so an `.init_array` constructor or any symbol-less code in a
    stripped binary is unreachable through `get_function`. This gives the
    handlers a fallback: point r2 at the binary and disassemble the address
    directly. Returns the adapter payload, or None if r2 is unavailable / no
    model is loaded.
    """
    if current_model is None:
        return None
    eng = get_engine()
    r2 = eng.registry.get("radare2")
    if r2 and r2.is_available():
        try:
            res = await r2.analyze(str(current_model.binary.path),
                                   {"mode": "disasm_at", "address": address,
                                    "count": count})
            if res and res.get("ok") and res.get("instructions"):
                return res
        except Exception as exc:  # r2pipe/backend failure — degrade gracefully
            logger.warning("raw_disasm_at(%s) failed: %s", address, exc)
    # Fallback: r2 unavailable, or its call-graph walk was defeated (an
    # ILT-heavy /INCREMENTAL PE64 returns nothing here). Disassemble the bytes
    # directly with capstone and resolve ILT thunk call targets.
    return _capstone_disasm_at(address, count)


def _capstone_disasm_at(address: str, count: int) -> dict | None:
    if current_model is None:
        return None
    if not current_model.binary.format.value.startswith("pe"):
        return None
    try:
        va = int(address, 16)
    except (TypeError, ValueError):
        return None
    from chimera.parsers.pe_disasm import disassemble_at
    insns = disassemble_at(current_model.binary.path, va, count)
    if not insns:
        return None

    def fmt(i: dict) -> str:
        s = f"0x{i['address']:x}: {i['mnemonic']} {i['op_str']}".rstrip()
        if "resolved_target" in i:
            s += f"  ; -> 0x{i['resolved_target']:x}"
        return s

    return {"ok": True, "address": address, "name": None, "backend": "capstone",
            "instruction_count": len(insns),
            "instructions": [fmt(i) for i in insns]}


async def raw_disasm_reply(address: str, extra: dict | None = None):
    """`raw_disasm_at` shaped into a handler reply, or None on no result.

    Lets get_function and get_disassembly share one raw-fallback shape: both
    call this on a function-map miss and fall through to their own error when
    it returns None. `extra` adds handler-specific fields (e.g. `layer`).
    """
    raw = await raw_disasm_at(address)
    if not (raw and raw.get("ok") and raw.get("instructions")):
        return None
    payload = {
        "address": raw["address"], "name": raw.get("name"), "raw": True,
        "instruction_count": raw["instruction_count"],
        "instructions": raw["instructions"],
    }
    if extra:
        payload.update(extra)
    return json_reply(payload)


# ---------------------------------------------------------------------------
# Cache access control
# ---------------------------------------------------------------------------
# `read_cache` takes a category name from the caller and uses it to reach into
# the on-disk cache, so it is a trust boundary: an LLM-supplied string must
# never be able to walk out of the cache directory.

_ALLOWED_CACHE_CATEGORIES = frozenset({
    "triage",
    "jadx",
    "manifest_xml",
    "info_plist",
    "class_dump",
})
_ALLOWED_CACHE_PREFIXES = ("r2_", "ghidra_")


def is_allowed_category(category: str) -> bool:
    """Whitelist-check a cache category. Rejects path traversal and unknown keys."""
    if not isinstance(category, str) or not category:
        return False
    # Rejection rule: any path-like characters
    if any(c in category for c in ("/", "\\", "..")):
        return False
    if category in _ALLOWED_CACHE_CATEGORIES:
        return True
    return any(category.startswith(prefix) for prefix in _ALLOWED_CACHE_PREFIXES)
