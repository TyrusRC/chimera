"""Tests for the Sidekick-style verifier pass over proposed renames."""

from __future__ import annotations

import json

import pytest

from chimera.ai import VerifyResult, verify_rename, verify_rename_prompt
from chimera.ai import verify as verify_mod


def test_verify_rename_prompt_returns_two_nonempty_strings():
    sys_p, user_p = verify_rename_prompt(
        "int add(int a, int b) { return a + b; }",
        suggested_name="add_two_ints",
        callers=["main"],
        callees=[],
    )
    assert isinstance(sys_p, str) and sys_p.strip()
    assert isinstance(user_p, str) and user_p.strip()
    # Sanity: the prompt must surface the rename and ask for JSON.
    assert "add_two_ints" in user_p
    assert "JSON" in user_p
    assert "accepted" in user_p
    # Verifier defaults to refute — confirm the language is present.
    assert "refute" in sys_p.lower() or "refuted=true" in user_p


def test_verify_rename_prompt_handles_empty_neighbors():
    sys_p, user_p = verify_rename_prompt(
        "void f(){}", suggested_name="f",
    )
    assert "(none)" in user_p


def test_verify_result_round_trips_json():
    vr = VerifyResult(accepted=True, confidence=0.83, reason="callers match")
    raw = vr.to_json()
    parsed = VerifyResult.from_json(raw)
    assert parsed == vr
    # to_json is real JSON
    data = json.loads(raw)
    assert data == {"accepted": True, "confidence": 0.83, "reason": "callers match"}


def test_verify_result_from_json_clamps_and_defaults():
    vr = VerifyResult.from_json('{"accepted": false}')
    assert vr.accepted is False
    assert vr.confidence == 0.0
    assert vr.reason == ""


class _StubClient:
    """Trivial stand-in for chimera.ai.client.AIClient.

    Holds the reply the test wants to observe and records prompts.
    """

    def __init__(self, reply: str):
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, *, max_tokens=None) -> str:
        self.calls.append((system, user))
        return self.reply


def test_verify_rename_accepts_when_verifier_returns_accept():
    client = _StubClient('{"accepted": true, "confidence": 0.9, "reason": "ok"}')
    vr = verify_rename(
        "int add(int a, int b){return a+b;}",
        "add_two_ints",
        client=client,
    )
    assert vr.accepted is True
    assert vr.confidence == pytest.approx(0.9)
    assert vr.reason == "ok"
    assert len(client.calls) == 1


def test_verify_rename_refutes_when_verifier_says_so():
    client = _StubClient(
        '{"accepted": false, "confidence": 0.2, "reason": "no evidence"}'
    )
    vr = verify_rename("...", "wrong_name", client=client)
    assert vr.accepted is False
    assert vr.reason == "no evidence"


def test_verify_rename_fail_closed_on_unparseable_response():
    client = _StubClient("not json at all")
    vr = verify_rename("...", "x", client=client)
    assert vr.accepted is False
    assert vr.confidence == 0.0
    assert "unparseable" in vr.reason.lower()


def test_verify_rename_extracts_json_from_prose():
    client = _StubClient(
        'Sure! {"accepted": true, "confidence": 0.7, "reason": "matches"} done.'
    )
    vr = verify_rename("...", "x", client=client)
    assert vr.accepted is True
    assert vr.confidence == pytest.approx(0.7)


def test_verify_rename_strips_code_fences():
    client = _StubClient(
        '```json\n{"accepted": true, "confidence": 0.6, "reason": "ok"}\n```'
    )
    vr = verify_rename("...", "x", client=client)
    assert vr.accepted is True


def test_verify_rename_uses_default_client_when_none_passed(monkeypatch):
    captured = {}

    class _Fake:
        def complete(self, system, user, *, max_tokens=None):
            captured["called"] = True
            return '{"accepted": false, "confidence": 0.0, "reason": "stub"}'

    monkeypatch.setattr(verify_mod, "default_client", lambda: _Fake())
    vr = verify_rename("code", "name")
    assert captured.get("called") is True
    assert vr.accepted is False


def test_verify_rename_fail_closed_on_client_error():
    from chimera.ai.client import AIError

    class _Boom:
        def complete(self, system, user, *, max_tokens=None):
            raise AIError("HTTP 500")

    vr = verify_rename("code", "name", client=_Boom())
    assert vr.accepted is False
    assert "verifier call failed" in vr.reason
