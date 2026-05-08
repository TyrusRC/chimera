from __future__ import annotations
from pathlib import Path

import pytest

from chimera.parsers.android_manifest import parse_manifest, ManifestModel

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


def test_parse_clean_manifest_returns_typed_model():
    model = parse_manifest(FIXTURES / "clean.xml")
    assert isinstance(model, ManifestModel)
    assert model.package == "com.example.clean"
    assert model.target_sdk_version == 34
    assert model.min_sdk_version == 28
    assert model.permissions == ["android.permission.INTERNET"]
    assert model.application.debuggable is False
    assert model.application.allow_backup is False
    assert model.application.full_backup_content == "@xml/backup_rules"
    assert model.application.network_security_config == "@xml/network_security_config"
    assert len(model.activities) == 1
    activity = model.activities[0]
    assert activity.name == ".MainActivity"
    assert activity.exported is False
    assert activity.has_intent_filter is True
    assert activity.permission is None
