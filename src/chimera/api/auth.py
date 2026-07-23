"""Optional bearer-token auth for the HTTP API.

Secure-by-default without breaking the local dev/test workflow:

- If ``CHIMERA_API_TOKEN`` is set, every API request must present
  ``Authorization: Bearer <token>`` (constant-time compared). Missing → 401,
  wrong → 403. This is the posture to use for any network-exposed deployment.
- If it's unset, auth is disabled and a one-time warning is logged. Combined
  with the default localhost bind (`chimera serve --host 127.0.0.1`) this keeps
  the single-user desktop workflow frictionless.

WebSocket routes are not covered by an HTTP dependency; treat them as trusted
only behind the same localhost bind / reverse proxy that fronts the API.
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import Header, HTTPException

logger = logging.getLogger(__name__)

_warned = False


def _expected_token() -> str | None:
    tok = os.environ.get("CHIMERA_API_TOKEN", "").strip()
    return tok or None


async def require_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency enforcing bearer auth when a token is configured."""
    global _warned
    expected = _expected_token()
    if expected is None:
        if not _warned:
            logger.warning(
                "CHIMERA_API_TOKEN not set — API authentication is DISABLED. "
                "Bind to localhost only (the default), or set the token before "
                "exposing the API on a network interface."
            )
            _warned = True
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    presented = authorization[len("Bearer "):].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=403, detail="invalid token")
