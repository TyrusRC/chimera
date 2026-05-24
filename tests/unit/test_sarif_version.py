"""SARIF driver version should track the installed chimera package version."""
from __future__ import annotations

from chimera import __version__
from chimera.detection_engineering.sarif_export import findings_to_sarif


def test_sarif_default_driver_version_matches_package():
    doc = findings_to_sarif([])
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "chimera"
    assert driver["version"] == __version__
    # belt-and-braces: should not be the legacy hardcoded value unless the
    # package legitimately bumps to 1.0.0
    if __version__ != "1.0.0":
        assert driver["version"] != "1.0.0"


def test_sarif_explicit_override_still_works():
    doc = findings_to_sarif([], tool_version="9.9.9-test")
    assert doc["runs"][0]["tool"]["driver"]["version"] == "9.9.9-test"
