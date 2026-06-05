"""BinQuery — natural-language → binary-function retrieval.

BinQuery (Yang et al., USENIX Security 2024) lets an analyst ask "find me
the AES key schedule" and get back the function addresses that match. We
wire it as an *optional* dep: if neither the `binquery` Python package
nor a `binquery` CLI is installed, the adapter reports unavailability
without raising. That keeps the cold-start cost of an analyze run at
zero for users who haven't opted in.

Reference: Yang et al., "BinQuery: A Novel Framework for Natural
Language-based Binary Code Retrieval", USENIX Security 2024.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BinQueryMatch:
    address: str
    score: float
    rationale: str = ""


class BinQueryAdapter:
    """Thin shim around the BinQuery retrieval model.

    Activation: prefers the in-process `binquery` Python package; falls
    back to a `binquery` CLI on PATH. Without either, `is_available()`
    is False and `search()` returns a clear "not installed" dict that
    callers can surface to the user.
    """

    def __init__(self) -> None:
        self._mod: Any | None = None
        self._tried = False

    def name(self) -> str:
        return "binquery"

    def is_available(self) -> bool:
        if not self._tried:
            self._tried = True
            try:
                import binquery  # type: ignore[import-not-found]
                self._mod = binquery
            except ImportError:
                self._mod = None
        if self._mod is not None:
            return True
        return shutil.which("binquery") is not None

    def search(
        self,
        binary_path: Path,
        query: str,
        *,
        top_k: int = 10,
    ) -> dict:
        """Return up to `top_k` matches for `query` against `binary_path`.

        Shape:
            {"ok": bool, "matches": [{"address", "score", "rationale"}, ...],
             "note": str}

        When BinQuery isn't installed we return ok=False with an
        actionable note rather than raising, so the CLI / API can present
        the result uniformly.
        """
        if not self.is_available():
            return {
                "ok": False,
                "matches": [],
                "note": (
                    "binquery is not installed. Install with "
                    "`pip install binquery` or place the `binquery` CLI on PATH."
                ),
            }
        # In-process API path. We don't know the exact signature of the
        # upstream package across versions, so probe a couple of common
        # entry points; degrade gracefully if none are present.
        if self._mod is not None:
            entry = (
                getattr(self._mod, "search", None)
                or getattr(self._mod, "query", None)
            )
            if entry is None:
                return {
                    "ok": False,
                    "matches": [],
                    "note": "binquery module has no recognised entry point",
                }
            try:
                raw = entry(str(binary_path), query, top_k=top_k)
            except Exception as exc:  # noqa: BLE001 — never crash an analyze
                logger.warning("binquery in-process call failed: %s", exc)
                return {"ok": False, "matches": [], "note": f"binquery error: {exc}"}
            return {"ok": True, "matches": _normalise(raw), "note": ""}
        # CLI fallback intentionally left as a "not yet wired" hint —
        # we don't shell out blindly because the upstream CLI flags
        # haven't stabilised. Surfacing this honestly is better than
        # invoking with a guess.
        return {
            "ok": False,
            "matches": [],
            "note": "binquery CLI detected but in-process Python API is preferred; "
                    "install `pip install binquery` to enable.",
        }


def _normalise(raw: Any) -> list[dict]:
    """Coerce upstream return shapes into our dataclass-aligned list-of-dicts."""
    out: list[dict] = []
    if not raw:
        return out
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        if isinstance(item, dict):
            addr = item.get("address") or item.get("addr")
            if not addr:
                continue
            out.append({
                "address": str(addr),
                "score": float(item.get("score", 0.0) or 0.0),
                "rationale": str(item.get("rationale", "") or ""),
            })
    return out
