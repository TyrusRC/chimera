"""Sidekick-style verification pass for proposed function renames.

Inspired by the Sidekick workflow (verifier-as-second-pass): after the
primary suggestion model proposes a name, a *separate* LLM call is asked
to *refute* it. The verifier defaults to refuted=True; the model must
produce evidence from the code to accept a rename. Empirically this
catches the failure mode where the first model latches onto a single
suggestive call (e.g. a `strlen` inside an unrelated handler) and emits
a confident-but-wrong name.

The verifier is intentionally cheap — short max_tokens, terse prompt,
strict JSON. Callers gate auto-apply on the combined first-pass
confidence AND verifier accept.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Optional

from chimera.ai.client import AIClient, AIError, default_client
from chimera.ai.parsing import strip_fence
from chimera.ai.prompts import verify_rename_prompt


@dataclass
class VerifyResult:
    """Outcome of the verifier pass over a proposed rename.

    `accepted` is the only field the caller MUST respect. `confidence`
    and `reason` are for telemetry and analyst-visible explanations.
    """

    accepted: bool
    confidence: float
    reason: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "VerifyResult":
        data = json.loads(raw)
        return cls(
            accepted=bool(data.get("accepted", False)),
            confidence=float(data.get("confidence", 0.0)),
            reason=str(data.get("reason", "")),
        )


def _parse_verify_payload(raw: str) -> VerifyResult:
    """Parse the verifier's JSON reply, defaulting to refuted on garbage.

    The verifier is fail-closed: a malformed model response counts as a
    refusal rather than an acceptance, so we never apply a name on the
    back of a parse error.
    """
    txt = strip_fence(raw)
    if not txt.startswith("{"):
        lo = txt.find("{")
        hi = txt.rfind("}")
        if lo != -1 and hi != -1 and hi > lo:
            txt = txt[lo : hi + 1]
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        return VerifyResult(accepted=False, confidence=0.0,
                            reason="verifier returned unparseable JSON")
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return VerifyResult(
        accepted=bool(data.get("accepted", False)),
        confidence=max(0.0, min(1.0, conf)),
        reason=str(data.get("reason", "")).strip(),
    )


def verify_rename(
    decomp_code: str,
    suggested_name: str,
    callers: Optional[list[str]] = None,
    callees: Optional[list[str]] = None,
    *,
    client: Optional[AIClient] = None,
) -> VerifyResult:
    """Ask a second LLM pass to refute `suggested_name`.

    Returns a `VerifyResult` whose `accepted` is True only when the
    verifier produced evidence-based acceptance. On any client-side
    error the result is refuted with a populated `reason` so the caller
    can log it without crashing the batch.
    """
    cli = client or default_client()
    sys_p, user_p = verify_rename_prompt(
        decomp_code,
        suggested_name=suggested_name,
        callers=callers,
        callees=callees,
    )
    try:
        raw = cli.complete(sys_p, user_p, max_tokens=200)
    except AIError as exc:
        return VerifyResult(accepted=False, confidence=0.0,
                            reason=f"verifier call failed: {exc}")
    return _parse_verify_payload(raw)
