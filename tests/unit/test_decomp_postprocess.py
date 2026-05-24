"""Post-processor passes lift Ghidra-style decomp output into readable C."""
from __future__ import annotations

from pathlib import Path

import pytest

from chimera.core.overlay import ProjectOverlay
from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo, ImportEntry
from chimera.model.program import UnifiedProgramModel
from chimera.report.decomp_postprocess import post_process


SHA = "c" * 64
ADDR = "0x140001000"


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        path=Path("/tmp/x"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.PE64, platform=Platform.WINDOWS, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address=ADDR, name="decode_license", original_name="FUN_140001000",
        language="c", classification="crypto", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x140002000", name="emit_log", original_name="emit_log",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_string(address="0x140005000", value="license key invalid")
    m.add_string(address="0x140005010", value="\nflag found")
    m.add_import(ImportEntry(dll="kernel32.dll", name="LoadLibraryA", address="0x140006000"))
    return m




def test_dat_ref_becomes_string_literal():
    m = _model()
    raw = 'puts(DAT_00140005000);'
    out = post_process(raw, m, ADDR)
    assert '"license key invalid"' in out.code
    assert out.inserted_strings == 1
    assert "DAT_00140005000" not in out.code


def test_string_escaping_handles_newlines():
    m = _model()
    raw = 'fputs(DAT_00140005010, stderr);'
    out = post_process(raw, m, ADDR)
    # Embedded newline must be escaped — otherwise we'd break the C source.
    assert '"\\nflag found"' in out.code


def test_ptr_ref_becomes_import_name():
    m = _model()
    raw = '(*PTR_00140006000)(dll_name);'
    out = post_process(raw, m, ADDR)
    assert "kernel32.dll!LoadLibraryA" in out.code


def test_fun_ref_becomes_recovered_name():
    m = _model()
    raw = 'iVar1 = FUN_00140002000(buf, len);'
    out = post_process(raw, m, ADDR)
    assert "emit_log" in out.code
    assert "FUN_00140002000" not in out.code


def test_self_fun_ref_is_not_inflated():
    """We shouldn't rewrite a placeholder name back to itself."""
    m = _model()
    m._functions["0x140001000"].name = "FUN_140001000"  # placeholder == name
    raw = 'FUN_00140001000(x);'
    out = post_process(raw, m, ADDR)
    # No-op: the substitution would be a tautology, so we kept the placeholder.
    assert "FUN_00140001000" in out.code


def test_local_renaming_drops_ivar_to_typed_form():
    m = _model()
    raw = 'iVar1 = 0; uVar2 = 1; pcVar3 = (char*)0;'
    out = post_process(raw, m, ADDR)
    assert "i1" in out.code and "u2" in out.code and "pstr3" in out.code


def test_overlay_variable_rename_applies():
    m = _model()
    o = ProjectOverlay(sha256=SHA)
    o.rename_variable(ADDR, "iVar1", "license_byte")
    raw = "iVar1 = buf[0]; if (iVar1 == 0) return 1;"
    out = post_process(raw, m, ADDR, overlay=o)
    assert "license_byte" in out.code
    # Two replacements within one line.
    assert out.code.count("license_byte") == 2


def test_overlay_global_comment_prepends_banner():
    m = _model()
    o = ProjectOverlay(sha256=SHA)
    o.add_comment(ADDR, 0, "license check; verified by RE 2026-05-22")
    raw = "return 0;"
    out = post_process(raw, m, ADDR, overlay=o)
    assert out.code.startswith("// license check; verified by RE 2026-05-22\n")


def test_well_known_magic_constants_get_labelled():
    m = _model()
    raw = "if (header == 0xdeadbeef) abort();"
    out = post_process(raw, m, ADDR)
    assert "DEADBEEF_SENTINEL" in out.code


def test_no_decompiled_input_passes_through_safely():
    m = _model()
    out = post_process("", m, ADDR)
    assert out.code == ""
    assert out.substitutions == 0


def test_unknown_addresses_are_left_intact():
    m = _model()
    raw = "x = DAT_00999999999;"
    out = post_process(raw, m, ADDR)
    # No string at that address — keep the placeholder so the analyst can navigate.
    assert "DAT_00999999999" in out.code


def test_substitution_counter_is_accurate():
    m = _model()
    raw = "puts(DAT_00140005000); emit_log = FUN_00140002000;"
    out = post_process(raw, m, ADDR)
    # One DAT rewrite + one FUN rewrite + no FUN tautology + no locals.
    assert out.substitutions >= 2
    assert out.inserted_strings == 1
    assert out.inserted_names == 1


@pytest.mark.skipif("not __import__('shutil').which('c++filt') and not __import__('importlib').util.find_spec('cxxfilt')",
                    reason="No demangler available")
def test_cpp_demangling_replaces_mangled_symbol():
    m = _model()
    raw = "_ZN3foo3barEv(ctx);"
    out = post_process(raw, m, ADDR)
    # foo::bar() is the canonical demangle.
    assert "foo::bar" in out.code
