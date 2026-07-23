"""Pure (asyncpg-free) serialization helpers for the persistence layer.

Kept separate from `model.database` so the encode/decode logic can be unit
tested without importing asyncpg / a live pool.
"""

from __future__ import annotations

import json


def encode_sources(sources: list[str] | None) -> str:
    """Encode `FunctionInfo.sources` (merge provenance) for a TEXT column."""
    return json.dumps(list(sources or []))


def decode_sources(raw: object) -> list[str]:
    """Decode a `sources` TEXT column back to a list.

    Tolerates None (legacy rows / pre-column DBs) and malformed JSON by
    returning an empty list rather than raising.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []
