"""Firebase analyzer: error surfacing + tiered severity."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_firebase_corrupted_config_surfaces_error(tmp_path):
    from chimera.protocol.firebase import FirebaseAnalyzer
    (tmp_path / "google-services.json").write_text("{ not valid json")

    result = FirebaseAnalyzer().extract_config(tmp_path, platform="android")
    assert result.get("errors"), "malformed config must produce at least one error"
    assert any("json" in e.lower() or "decode" in e.lower() for e in result["errors"])


def test_firebase_valid_config_has_empty_errors(tmp_path):
    from chimera.protocol.firebase import FirebaseAnalyzer
    valid = {"project_info": {"project_id": "p", "firebase_url": "https://p.firebaseio.com"}}
    (tmp_path / "google-services.json").write_text(json.dumps(valid))

    result = FirebaseAnalyzer().extract_config(tmp_path, platform="android")
    assert result.get("errors") == [], "valid config must produce empty errors list"
    assert result["project_id"] == "p"


def test_firebase_severity_info_when_only_url_present():
    from chimera.protocol.firebase import FirebaseAnalyzer
    analyzer = FirebaseAnalyzer()
    findings = analyzer.check_misconfigurations({
        "database_url": "https://x.firebaseio.com",
    })
    assert any(f["severity"] == "info" for f in findings), findings


def test_firebase_severity_high_when_rules_open():
    from chimera.protocol.firebase import FirebaseAnalyzer
    analyzer = FirebaseAnalyzer()
    findings = analyzer.check_misconfigurations(
        {"database_url": "https://x.firebaseio.com"},
        rules_text='{"rules": {".read": true, ".write": true}}',
    )
    assert any(f["severity"] == "high" for f in findings), findings
