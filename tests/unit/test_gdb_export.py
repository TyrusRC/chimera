"""gdb-export emits a .gdbinit with convenience variables and a chimera-bp command."""
from __future__ import annotations

from pathlib import Path

import pytest

from chimera.cli import _emit_gdbinit, _sanitise_gdb_var
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel


SHA = "f" * 64


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        path=Path("/tmp/app"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.ELF, platform=Platform.LINUX_NATIVE,
        arch=Architecture.X86_64, framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="0x401000", name="decode_license", original_name="FUN_401000",
        language="c", classification="crypto", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x401200", name="emit_log", original_name="emit_log",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x401400", name="sym.imp.printf", original_name="sym.imp.printf",
        language="c", classification="library", layer="native", source_backend="r2",
    ))
    # PLT placeholder address — must be filtered out.
    m.add_function(FunctionInfo(
        address="0xffffffffffffffff", name="imp.libc_start_main", original_name="imp.libc_start_main",
        language="c", classification="library", layer="native", source_backend="r2",
    ))
    return m


def test_sanitise_gdb_var_accepts_simple_identifier():
    assert _sanitise_gdb_var("decode_license") == "decode_license"


def test_sanitise_gdb_var_replaces_dots_with_underscores():
    assert _sanitise_gdb_var("sym.imp.printf") == "sym_imp_printf"


def test_sanitise_gdb_var_strips_leading_digits():
    assert _sanitise_gdb_var("0xdeadbeef") == ""


def test_sanitise_gdb_var_empty_input():
    assert _sanitise_gdb_var("") == ""


def test_emit_gdbinit_writes_one_variable_per_function(tmp_path):
    out = tmp_path / "app.gdbinit"
    count = _emit_gdbinit(out, Path("/tmp/app"), _model())
    text = out.read_text()
    assert "set $decode_license = (void *)0x401000" in text
    assert "set $emit_log = (void *)0x401200" in text
    assert "set $sym_imp_printf = (void *)0x401400" in text
    # Filtered: placeholder PLT address.
    assert "0xffffffffffffffff" not in text
    # Banner + chimera-bp helper present.
    assert "define chimera-bp" in text
    assert "file /tmp/app" in text
    # Counter reflects the three emitted vars (placeholder skipped).
    assert count == 3
    assert "3 symbols" in text


def test_emit_gdbinit_dedupes_identical_sanitised_names(tmp_path):
    """Two functions whose names sanitise to the same identifier must not both emit."""
    bi = BinaryInfo(
        path=Path("/tmp/app"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.ELF, platform=Platform.LINUX_NATIVE,
        arch=Architecture.X86_64, framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="0x1000", name="foo.bar", original_name="foo.bar",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x2000", name="foo/bar", original_name="foo/bar",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    out = tmp_path / "x.gdbinit"
    count = _emit_gdbinit(out, Path("/tmp/app"), m)
    # Both sanitise to foo_bar — only the first wins.
    text = out.read_text()
    assert text.count("set $foo_bar = (void *)") == 1
    assert "0x1000" in text and "0x2000" not in text
    assert count == 1


def test_emit_gdbinit_handles_empty_model(tmp_path):
    bi = BinaryInfo(
        path=Path("/tmp/app"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.ELF, platform=Platform.LINUX_NATIVE,
        arch=Architecture.X86_64, framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    out = tmp_path / "x.gdbinit"
    count = _emit_gdbinit(out, Path("/tmp/app"), m)
    assert count == 0
    text = out.read_text()
    # The chimera-bp helper is still defined so the analyst's workflow doesn't break.
    assert "define chimera-bp" in text
