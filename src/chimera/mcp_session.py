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
