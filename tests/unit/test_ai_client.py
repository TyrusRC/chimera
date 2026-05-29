"""Tests for chimera.ai client and prompts.

We don't hit the real Anthropic API. Instead we monkey-patch
urllib.request.urlopen so the tests verify request shape (URL, headers,
body) and error-mapping (HTTPError → AIError, missing key → AINotConfigured).
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from chimera.ai import (
    AIClient,
    AIError,
    AINotConfigured,
    comment_prompt,
    default_client,
    explain_prompt,
    rename_prompt,
)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._buf.read()


def test_default_client_raises_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AINotConfigured):
        default_client()


def test_default_client_picks_up_model_override(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("CHIMERA_AI_MODEL", "claude-opus-4-8")
    c = default_client()
    assert c.model == "claude-opus-4-8"
    assert c.api_key == "sk-test"


def test_complete_sends_correct_request_shape(monkeypatch):
    captured: dict = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse({
            "content": [{"type": "text", "text": "hello world"}],
        })

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = AIClient(api_key="sk-test", model="claude-sonnet-4-6")
    out = client.complete("sys", "user")
    assert out == "hello world"
    assert captured["url"].endswith("/v1/messages")
    # urllib lowercases the first letter — match both forms
    headers_lower = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers_lower["x-api-key"] == "sk-test"
    assert headers_lower["anthropic-version"]
    assert captured["body"]["model"] == "claude-sonnet-4-6"
    assert captured["body"]["system"] == "sys"
    assert captured["body"]["messages"][0]["content"] == "user"


def test_complete_maps_http_error_to_ai_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 429, "Too Many Requests",
            hdrs={},
            fp=io.BytesIO(b'{"error":"rate_limit"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = AIClient(api_key="sk-test")
    with pytest.raises(AIError) as exc_info:
        client.complete("sys", "user")
    assert "429" in str(exc_info.value)


def test_complete_rejects_empty_completion(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse({"content": []})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = AIClient(api_key="sk-test")
    with pytest.raises(AIError):
        client.complete("sys", "user")


def test_explain_prompt_includes_metadata():
    sys_p, user_p = explain_prompt("int main(){}", function_name="main", address="0x100")
    assert "senior reverse engineer" in sys_p
    assert "main" in user_p
    assert "0x100" in user_p
    assert "int main()" in user_p


def test_rename_prompt_demands_single_line():
    sys_p, user_p = rename_prompt("...", current_name="FUN_001000")
    assert "single line" in user_p
    assert "snake_case" in user_p
    assert "FUN_001000" in user_p


def test_comment_prompt_targets_specific_line():
    _sys, user_p = comment_prompt("...", line=42)
    assert "line 42" in user_p
