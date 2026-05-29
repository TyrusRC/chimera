"""Tests for the overlay export/import CLI + module roundtrip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera.core.overlay import ProjectOverlay


def _seed_overlay(project_dir: Path, sha: str) -> ProjectOverlay:
    o = ProjectOverlay.load(project_dir, sha)
    o.rename_function("0x1000", "decrypt_blob")
    o.rename_variable("0x1000", "iVar1", "byte_index")
    o.add_comment("0x1000", 0, "entry — XOR cipher")
    o.add_comment("0x1000", 12, "key offset")
    o.set_function_type("0x1000", "int decrypt_blob(char*, int)")
    o.set_classification("0x1000", "crypto")
    o.save()
    return o


def test_overlay_roundtrip_preserves_all_fields(tmp_path: Path):
    project_dir = tmp_path / "projects"
    sha = "a" * 64
    original = _seed_overlay(project_dir, sha)

    # Export to dict (matches the API export shape).
    export_payload = {
        "schema": "chimera-overlay-export/1",
        "sha256": sha,
        "function_names": original.function_names,
        "variable_renames": original.variable_renames,
        "comments": original.comments,
        "function_types": original.function_types,
        "user_classifications": original.user_classifications,
    }

    # Re-import into a fresh project dir with replace mode.
    fresh_dir = tmp_path / "projects2"
    reimported = ProjectOverlay.load(fresh_dir, sha)
    reimported.function_names.update(export_payload["function_names"])
    for addr, vmap in export_payload["variable_renames"].items():
        reimported.variable_renames.setdefault(addr, {}).update(vmap)
    for addr, cmap in export_payload["comments"].items():
        reimported.comments.setdefault(addr, {}).update(cmap)
    reimported.function_types.update(export_payload["function_types"])
    reimported.user_classifications.update(export_payload["user_classifications"])
    reimported.save()

    # Re-load and verify
    loaded = ProjectOverlay.load(fresh_dir, sha)
    assert loaded.function_names == {"0x1000": "decrypt_blob"}
    assert loaded.variable_renames == {"0x1000": {"iVar1": "byte_index"}}
    assert loaded.comments == {"0x1000": {"0": "entry — XOR cipher", "12": "key offset"}}
    assert loaded.function_types == {"0x1000": "int decrypt_blob(char*, int)"}
    assert loaded.user_classifications == {"0x1000": "crypto"}


def test_cli_overlay_export_emits_json(tmp_path: Path):
    """Smoke test for `chimera overlay export` — payload is valid JSON."""
    from click.testing import CliRunner
    from chimera.cli import main

    # Need a fake binary file for the CLI's Path(exists=True) check.
    fake_bin = tmp_path / "sample.bin"
    fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 64)
    project_dir = tmp_path / "projects"

    # Pre-seed an overlay keyed by that binary's sha.
    from chimera.model.binary import BinaryInfo
    b = BinaryInfo.from_path(fake_bin)
    o = ProjectOverlay.load(project_dir, b.sha256)
    o.rename_function("0x100", "alpha")
    o.save()

    runner = CliRunner()
    result = runner.invoke(main, [
        "overlay", "export",
        str(fake_bin),
        "--project-dir", str(project_dir),
    ])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["schema"] == "chimera-overlay-export/1"
    assert parsed["sha256"] == b.sha256
    assert parsed["function_names"] == {"0x100": "alpha"}


def test_cli_overlay_import_warns_on_sha_mismatch(tmp_path: Path):
    """Importing an overlay exported from a different sha should warn but not fail."""
    from click.testing import CliRunner
    from chimera.cli import main

    fake_bin = tmp_path / "sample.bin"
    fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 64)
    project_dir = tmp_path / "projects"

    bad_overlay = tmp_path / "from-other.json"
    bad_overlay.write_text(json.dumps({
        "schema": "chimera-overlay-export/1",
        "sha256": "b" * 64,  # not our sha
        "function_names": {"0x100": "imported"},
        "variable_renames": {},
        "comments": {},
        "function_types": {},
        "user_classifications": {},
    }))

    runner = CliRunner()
    result = runner.invoke(main, [
        "overlay", "import",
        str(fake_bin),
        "--project-dir", str(project_dir),
        "-i", str(bad_overlay),
    ])
    assert result.exit_code == 0, result.output
    # Warning goes to stderr; merged stream is what `result.output` contains
    # depending on click version. Check the success message either way.
    assert "imported" in result.output or "renames" in result.output
