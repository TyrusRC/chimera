"""SARIF v2.1.0 export produces a schema-valid JSON document."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from chimera.detection_engineering.cvss_findings import Finding
from chimera.detection_engineering.sarif_export import findings_to_sarif


SCHEMA_PATH = Path(__file__).parent.parent / "fixtures" / "schemas" / "sarif-2.1.0-min.json"


def _finding(rule_id: str, severity: str = "Medium") -> Finding:
    return Finding(
        finding_id=rule_id,
        title=f"Title for {rule_id}",
        severity=severity,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_base_score=0.0,
        description=f"Description for {rule_id}",
        evidence=["AndroidManifest.xml:14 evidence text"],
        recommendation="fix it",
    )


def test_sarif_top_level_shape():
    doc = findings_to_sarif([_finding("R1"), _finding("R2", "High")])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].startswith("https://")
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "chimera"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2


def test_sarif_validates_against_schema_subset():
    schema = json.loads(SCHEMA_PATH.read_text())
    doc = findings_to_sarif([_finding("R1"), _finding("R2", "Critical")])
    jsonschema.validate(doc, schema)


def test_sarif_maps_severity_to_level():
    doc = findings_to_sarif([
        _finding("none_r", "None"),
        _finding("low_r", "Low"),
        _finding("med_r", "Medium"),
        _finding("high_r", "High"),
        _finding("crit_r", "Critical"),
    ])
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["none_r"] == "none"
    assert levels["low_r"] == "note"
    assert levels["med_r"] == "warning"
    assert levels["high_r"] == "error"
    assert levels["crit_r"] == "error"


def test_sarif_empty_findings_validates():
    doc = findings_to_sarif([])
    jsonschema.validate(doc, json.loads(SCHEMA_PATH.read_text()))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_location_uses_artifact_when_evidence_looks_file_like():
    doc = findings_to_sarif([_finding("R1")])
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    # AndroidManifest.xml prefix recognized → artifactLocation populated
    assert loc.get("artifactLocation", {}).get("uri") == "AndroidManifest.xml"
    assert "evidence text" in loc["region"]["snippet"]["text"]
