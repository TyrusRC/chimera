"""Tests for the Radare2Adapter — focus on _triage extension shape."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.mark.asyncio
async def test_triage_with_disasm_emits_per_function_disasm_class_symbols_cstring_pool(monkeypatch):
    from chimera.adapters import radare2 as r2_mod

    fake_r2 = MagicMock()
    # Canned responses for the r2 commands the adapter calls.
    canned = {
        "ij": '{"bin": {"arch": "arm64"}, "core": {}}',
        "izj": '[{"vaddr": 4297064640, "string": "validate:", "section": "__objc_methname"}]',
        "iij": '[]',
        "isj": '[{"name": "_OBJC_CLASS_$_Greeter", "vaddr": 4298965008, "type": "OBJ"}, '
               ' {"name": "sym.foo", "vaddr": 4299513856, "type": "FUNC"}]',
        "pdfj @ 0x100456000": (
            '{"name": "sym.foo", "offset": 4299513856, "ops": ['
            '{"offset": 4299513856, "type": "lea", '
            ' "disasm": "adrp x1, 0x100200000", "opcode": "adrp x1, 0x100200000", '
            ' "ptr": 4297064448}, '
            '{"offset": 4299513860, "type": "add", '
            ' "disasm": "add x1, x1, 0x40", "opcode": "add x1, x1, 0x40"}, '
            '{"offset": 4299513864, "type": "call", '
            ' "disasm": "bl sym.imp.objc_msgSend", "opcode": "bl 0x100123abc", '
            ' "ptr": 4296921276, "fcn_call": "sym.imp.objc_msgSend"}'
            ']}'
        ),
    }
    fake_r2.cmd.side_effect = lambda c: canned.get(c, "{}")
    monkeypatch.setattr(r2_mod, "r2pipe", MagicMock(open=MagicMock(return_value=fake_r2)))

    adapter = r2_mod.Radare2Adapter()
    result = await adapter.analyze("/tmp/fake.dylib", {"mode": "triage_with_disasm"})

    assert "per_function_disasm" in result
    assert "class_symbols" in result
    assert "cstring_pool" in result
    # class_symbols should map "Greeter" -> hex address
    assert "Greeter" in result["class_symbols"]
    # cstring_pool contains the selector string
    assert any(s == "validate:" for s in result["cstring_pool"].values())
    # per_function_disasm has at least the foo function with normalized ops
    assert "0x100456000" in result["per_function_disasm"] or "0x100456000".lower() in {
        k.lower() for k in result["per_function_disasm"]
    }


@pytest.mark.parametrize("disasm,expected_opcode,expected_operands", [
    ("ret", "ret", []),
    ("adrp x1, 0x100200000", "adrp", ["x1", 0x100200000]),
    ("add x1, x1, 0x40", "add", ["x1", "x1", 0x40]),
    ("ldr x0, [x8, 0x40]", "ldr", ["x0", "x8", 0x40]),
    ("mov x0, #0x1234", "mov", ["x0", 0x1234]),
    ("add x0, x0, -0x40", "add", ["x0", "x0", -0x40]),
    ("bl sym.imp.objc_msgSend", "bl", ["sym.imp.objc_msgSend"]),
    ("b.eq 0x100456000", "b.eq", [0x100456000]),
])
def test_normalize_op_parses_common_arm64_disasm(disasm, expected_opcode, expected_operands):
    from chimera.adapters.radare2 import _normalize_op

    op = {"offset": 0x1000, "disasm": disasm}
    result = _normalize_op(op)
    assert result["opcode"] == expected_opcode
    assert result["operands"] == expected_operands
