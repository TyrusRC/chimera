"""Minimal Anthropic Messages API client backed by urllib.

Why not the `anthropic` SDK? Adding a heavy SDK for one POST inflates the
wheel and slows cold starts. urllib is in the stdlib, the Messages API is
a single JSON endpoint, and the failure modes we care about (missing key,
401, 429, network) are easy to express directly.

If a user wants the official SDK, they can still set ANTHROPIC_BASE_URL to
their own proxy — this client respects it.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_API_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TIMEOUT_S = 30.0


class AIError(RuntimeError):
    """Catch-all for AI API failures (network, 5xx, malformed JSON)."""


class AINotConfigured(AIError):
    """Raised when ANTHROPIC_API_KEY is missing — surface as HTTP 503."""


@dataclass
class AIClient:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    api_version: str = DEFAULT_API_VERSION
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout_s: float = DEFAULT_TIMEOUT_S

    def complete(self, system: str, user: str, *, max_tokens: Optional[int] = None) -> str:
        """Single-turn completion. Returns the assistant's text content.

        Raises AIError on any non-2xx response or transport failure.
        """
        body = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/v1/messages",
            data=body,
            method="POST",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": self.api_version,
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise AIError(f"HTTP {exc.code} from Anthropic: {err_body[:500]}") from exc
        except urllib.error.URLError as exc:
            raise AIError(f"Network error talking to Anthropic: {exc.reason}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AIError(f"Malformed JSON from Anthropic: {exc}") from exc
        # Anthropic returns content as a list of blocks; we want the text.
        blocks = payload.get("content") or []
        out = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not out:
            raise AIError(f"Empty completion: {payload!r}")
        return out


def default_client() -> AIClient:
    """Construct an AIClient from the environment.

    Raises AINotConfigured when no key is set so callers can map to a clear
    503 instead of a generic 500.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise AINotConfigured(
            "ANTHROPIC_API_KEY is not set. AI features are disabled. "
            "Set the env var and restart chimera to enable explain/rename/comment."
        )
    return AIClient(
        api_key=api_key,
        model=os.environ.get("CHIMERA_AI_MODEL", DEFAULT_MODEL),
        base_url=os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL),
    )
