"""Capstone x64 disassembly fallback with ILT thunk resolution.

When r2's call-graph walk is defeated (an ILT-heavy /INCREMENTAL PE64) it
returns nothing for a raw address, leaving get_disassembly/get_function blind.
This fallback disassembles the bytes directly and annotates calls/jumps that go
through an Incremental Link Table thunk with their real target.

The disassembly core works on raw bytes (no PE needed), so the tests pin it
directly; ILT annotation is tested with a stub resolver.
"""
from __future__ import annotations

import pytest

capstone = pytest.importorskip("capstone")  # the optional [disasm] extra

from chimera.parsers.pe_disasm import annotate_ilt, disasm_bytes


def test_disasm_bytes_decodes_x64():
    # mov qword ptr [rsp + 8], rcx ; ret
    code = bytes.fromhex("48894c2408") + b"\xc3"
    insns = disasm_bytes(code, 0x140001000, count=8)
    assert insns[0]["address"] == 0x140001000
    assert insns[0]["mnemonic"] == "mov"
    assert "rcx" in insns[0]["op_str"]
    assert insns[1]["mnemonic"] == "ret"


def test_disasm_bytes_respects_count():
    code = b"\x90" * 10  # ten NOPs
    assert len(disasm_bytes(code, 0x1000, count=4)) == 4


def test_annotate_ilt_resolves_call_through_thunk():
    # a call whose target is an ILT thunk gets the real callee attached
    insn = {"address": 0x140010000, "mnemonic": "call",
            "op_str": "0x140003e0e", "bytes": "e8..."}
    def resolver(va):
        return 0x14000af00 if va == 0x140003e0e else None
    annotate_ilt(insn, resolver)
    assert insn["resolved_target"] == 0x14000af00


def test_annotate_ilt_noop_for_non_thunk_call():
    insn = {"address": 0x140010000, "mnemonic": "call", "op_str": "0x140050000"}
    annotate_ilt(insn, lambda va: None)
    assert "resolved_target" not in insn


def test_annotate_ilt_ignores_non_control_flow():
    insn = {"address": 0x1, "mnemonic": "mov", "op_str": "rax, 0x140003e0e"}
    annotate_ilt(insn, lambda va: 0x14000af00)
    assert "resolved_target" not in insn
