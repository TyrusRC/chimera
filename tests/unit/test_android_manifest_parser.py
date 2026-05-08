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


def test_parse_records_application_line():
    model = parse_manifest(FIXTURES / "debuggable.xml")
    # <application ...> opens on line 5 in the fixture
    assert model.application.line == 5
    assert model.application.debuggable is True
    assert model.application.allow_backup is True


def test_implicit_export_via_intent_filter():
    model = parse_manifest(FIXTURES / "exported_no_perm.xml")
    by_name = {a.name: a for a in model.services}
    svc = by_name[".Svc"]
    # exported attr not set → exported is None, but has_intent_filter is True
    assert svc.exported is None
    assert svc.has_intent_filter is True


def test_provider_with_explicit_permission():
    model = parse_manifest(FIXTURES / "exported_no_perm.xml")
    p = model.providers[0]
    assert p.permission == "com.example.expo.READ"
    assert p.exported is True
