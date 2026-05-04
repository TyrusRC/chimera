"""Unit tests for the OLLVM heuristic detector."""

from __future__ import annotations

from chimera.bypass.ollvm_detector import (
    OllvmFinding, detect_ollvm_in_disasm, summarize,
)


def _op(offset: int, opcode: str, *operands) -> dict:
    return {"offset": offset, "opcode": opcode,
            "operands": list(operands), "target_sym": None}


def test_normal_function_no_findings():
    """A linear function with one block shouldn't trigger any heuristic."""
    ops = [
        _op(0x100, "mov", "x0", "x1"),
        _op(0x104, "add", "x0", "x0", 1),
        _op(0x108, "ret"),
    ]
    findings = detect_ollvm_in_disasm({"0x100": {"name": "f", "ops": ops}})
    assert findings == []


def test_cff_dispatcher_detected():
    """Synthesize a function where most edges target one block."""
    # 35 blocks, all branch back to the same dispatcher offset 0x100. The
    # threshold is tuned to reject natural ~20-block dispatchers so we
    # need a clearly OLLVM-sized example here.
    ops = [_op(0x100, "ldr", "w0", "x1")]
    addr = 0x110
    for _ in range(35):
        ops += [
            _op(addr, "mov", "x0", "x1"),
            _op(addr + 4, "b", 0x100),  # branch back to dispatcher
        ]
        addr += 8
    findings = detect_ollvm_in_disasm({"0x100": {"name": "fcff", "ops": ops}})
    techs = {f.technique for f in findings}
    assert "ollvm_cff" in techs


def test_summarize_groups_by_technique():
    findings = [
        OllvmFinding("a", "0x1", "ollvm_cff", 0.5, ""),
        OllvmFinding("b", "0x2", "ollvm_cff", 0.5, ""),
        OllvmFinding("c", "0x3", "ollvm_isub", 0.6, ""),
    ]
    summary = summarize(findings)
    assert summary == {"ollvm_cff": 2, "ollvm_isub": 1}


def test_empty_input_returns_empty():
    assert detect_ollvm_in_disasm({}) == []
    assert detect_ollvm_in_disasm({"0x0": {"name": "x", "ops": []}}) == []
