"""ProjectOverlay round-trips renames/comments/types and applies to the model."""
from __future__ import annotations

from pathlib import Path

import pytest

from chimera.core.overlay import OVERLAY_SCHEMA, ProjectOverlay, _normalize_addr
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel


SHA = "a" * 64


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        path=Path("/tmp/x"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="0x140001000", name="FUN_140001000", original_name="FUN_140001000",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x140001200", name="entry", original_name="entry",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    return m


def test_normalize_addr_handles_int_hex_and_uppercase():
    assert _normalize_addr(0x100) == "0x100"
    assert _normalize_addr("0x100") == "0x100"
    assert _normalize_addr("0X0000100") == "0x100"
    assert _normalize_addr("100") == "0x100"  # treated as hex


def test_overlay_roundtrip(tmp_path):
    o = ProjectOverlay.load(tmp_path, SHA)
    assert o.function_names == {}
    o.rename_function("0x140001000", "decode_license")
    o.rename_variable("0x140001000", "iVar1", "license_byte")
    o.add_comment("0x140001000", 0, "Entry block")
    o.set_function_type("0x140001000", "int decode_license(char*)")
    o.set_classification("0x140001000", "crypto")
    o.save()

    # Re-read from a fresh handle so we exercise the disk path.
    o2 = ProjectOverlay.load(tmp_path, SHA)
    assert o2.function_names["0x140001000"] == "decode_license"
    assert o2.variable_renames["0x140001000"]["iVar1"] == "license_byte"
    assert o2.comments["0x140001000"]["0"] == "Entry block"
    assert o2.function_types["0x140001000"] == "int decode_license(char*)"
    assert o2.user_classifications["0x140001000"] == "crypto"


def test_overlay_save_writes_schema_field(tmp_path):
    o = ProjectOverlay.load(tmp_path, SHA)
    o.rename_function("0x100", "foo")
    o.save()
    import json
    data = json.loads((tmp_path / SHA / "overlay.json").read_text())
    assert data["schema"] == OVERLAY_SCHEMA
    assert data["function_names"]["0x100"] == "foo"


def test_overlay_load_missing_returns_empty(tmp_path):
    o = ProjectOverlay.load(tmp_path, SHA)
    assert o.sha256 == SHA
    assert o.function_names == {}


def test_overlay_load_corrupt_file_returns_empty(tmp_path):
    overlay_dir = tmp_path / SHA
    overlay_dir.mkdir()
    (overlay_dir / "overlay.json").write_text("{not valid json")
    o = ProjectOverlay.load(tmp_path, SHA)
    # We do not raise — analyst work continues with a fresh overlay.
    assert o.function_names == {}


def test_apply_to_model_overrides_function_name():
    m = _model()
    o = ProjectOverlay(sha256=SHA)
    o.rename_function("0x140001000", "decode_license")
    o.set_function_type("0x140001000", "int decode_license(char*)")
    o.set_classification("0x140001000", "crypto")

    touched = o.apply_to_model(m)
    assert touched == 1

    f = m.get_function("0x140001000")
    assert f.name == "decode_license"
    assert f.signature == "int decode_license(char*)"
    assert f.classification == "crypto"

    # Untouched function keeps its r2 name.
    g = m.get_function("0x140001200")
    assert g.name == "entry"


def test_save_without_path_raises():
    o = ProjectOverlay(sha256=SHA)
    with pytest.raises(RuntimeError):
        o.save()


def test_delete_function_name(tmp_path):
    o = ProjectOverlay.load(tmp_path, SHA)
    o.rename_function("0x100", "foo")
    assert o.delete_function_name("0x100") is True
    assert o.delete_function_name("0x100") is False
    assert "0x100" not in o.function_names


def test_address_normalisation_is_stable(tmp_path):
    """Renames keyed by different surface forms should overwrite each other."""
    o = ProjectOverlay.load(tmp_path, SHA)
    o.rename_function("0x100", "name_v1")
    o.rename_function("0X0000100", "name_v2")
    assert o.function_names == {"0x100": "name_v2"}
