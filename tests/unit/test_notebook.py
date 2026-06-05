"""Notebook overlay round-trip + tag filter + persistence."""
from __future__ import annotations

import json
from pathlib import Path

from chimera.core.overlay import ProjectOverlay


SHA = "n" * 64


def _fresh(tmp_path: Path) -> ProjectOverlay:
    return ProjectOverlay.load(tmp_path, SHA)


def test_add_list_update_remove_roundtrip(tmp_path):
    ov = _fresh(tmp_path)
    nid = ov.add_note(
        title="Suspicious license check",
        body="Looks like the binary XORs the license with a static key.",
        tags=["crypto", "license"],
        evidence=[{"address": "0X140001000", "line": 12}],
    )
    assert nid in ov.notes
    entry = ov.notes[nid]
    # Address is normalised to lowercase 0x form.
    assert entry["evidence"] == [{"address": "0x140001000", "line": 12}]
    assert entry["tags"] == ["crypto", "license"]
    assert entry["created_at"] == entry["updated_at"]
    listed = ov.list_notes()
    assert len(listed) == 1 and listed[0]["id"] == nid

    # Update touches updated_at.
    prev_updated = entry["updated_at"]
    ok = ov.update_note(nid, title="Static key XOR", tags=["crypto", "crypto"])
    assert ok
    assert ov.notes[nid]["title"] == "Static key XOR"
    # Dedupe preserved order.
    assert ov.notes[nid]["tags"] == ["crypto"]
    assert ov.notes[nid]["updated_at"] >= prev_updated

    assert ov.update_note("no-such-id", title="x") is False

    # Remove.
    assert ov.remove_note(nid) is True
    assert nid not in ov.notes
    assert ov.remove_note(nid) is False


def test_tag_filter_and_sort_newest_first(tmp_path):
    ov = _fresh(tmp_path)
    a = ov.add_note(title="A", body="", tags=["x"])
    b = ov.add_note(title="B", body="", tags=["x", "y"])
    c = ov.add_note(title="C", body="", tags=["y"])

    # Force distinct timestamps so sort order is unambiguous.
    ov.notes[a]["created_at"] = "2024-01-01T00:00:00+00:00"
    ov.notes[b]["created_at"] = "2024-01-02T00:00:00+00:00"
    ov.notes[c]["created_at"] = "2024-01-03T00:00:00+00:00"

    x_titles = [e["title"] for e in ov.list_notes(tag="x")]
    assert x_titles == ["B", "A"]
    y_titles = [e["title"] for e in ov.list_notes(tag="y")]
    assert y_titles == ["C", "B"]
    assert ov.list_notes(tag="nope") == []


def test_save_load_roundtrip_with_notes(tmp_path):
    ov = _fresh(tmp_path)
    nid = ov.add_note(
        title="Finding 1",
        body="b",
        tags=["t"],
        evidence=[{"address": "0x100", "line": 4}],
    )
    # Co-existence with other overlay fields.
    ov.rename_function("0x100", "decode")
    ov.add_comment("0x100", 0, "entry")
    ov.save()

    reloaded = ProjectOverlay.load(tmp_path, SHA)
    assert nid in reloaded.notes
    assert reloaded.notes[nid]["title"] == "Finding 1"
    assert reloaded.notes[nid]["evidence"] == [{"address": "0x100", "line": 4}]
    assert reloaded.function_names["0x100"] == "decode"
    assert reloaded.comments["0x100"]["0"] == "entry"

    # On-disk JSON includes the notes key.
    raw = json.loads((tmp_path / SHA / "overlay.json").read_text())
    assert "notes" in raw and nid in raw["notes"]


def test_evidence_malformed_inputs_are_skipped(tmp_path):
    ov = _fresh(tmp_path)
    nid = ov.add_note(
        title="t",
        body="b",
        evidence=[
            {"address": "0x10", "line": "7"},          # str line coerced
            {"address": "", "line": 0},                 # empty addr dropped
            {"line": 3},                                # missing addr dropped
            "not-a-dict",                               # non-dict dropped
            {"address": "0x20"},                        # default line=0
        ],
    )
    ev = ov.notes[nid]["evidence"]
    assert ev == [
        {"address": "0x10", "line": 7},
        {"address": "0x20", "line": 0},
    ]


def test_update_note_evidence_replaces(tmp_path):
    ov = _fresh(tmp_path)
    nid = ov.add_note(title="t", body="b",
                      evidence=[{"address": "0x1", "line": 0}])
    ov.update_note(nid, evidence=[{"address": "0x2", "line": 5}])
    assert ov.notes[nid]["evidence"] == [{"address": "0x2", "line": 5}]
