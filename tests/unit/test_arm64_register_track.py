"""Unit tests for ARM64 register state vocabulary."""
from __future__ import annotations


def test_register_state_starts_empty_with_unknown():
    from chimera.parsers.arm64_register_track import RegisterState, Unknown

    s = RegisterState()
    assert s.get("x0") == Unknown
    assert s.get("x1") == Unknown


def test_constant_pool_value_carries_address():
    from chimera.parsers.arm64_register_track import ConstantPool

    v = ConstantPool(0x100200040)
    assert v.address == 0x100200040


def test_class_symbol_value_carries_name():
    from chimera.parsers.arm64_register_track import ClassSymbol

    v = ClassSymbol("LoginVC")
    assert v.name == "LoginVC"


def test_alloc_result_value_carries_class_name():
    from chimera.parsers.arm64_register_track import AllocResult

    v = AllocResult("Greeter")
    assert v.class_name == "Greeter"


def test_entry_x0_and_super_are_singletons():
    from chimera.parsers.arm64_register_track import EntryX0, Super

    assert EntryX0 is EntryX0
    assert Super is Super


def test_register_state_set_and_get_roundtrip():
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, EntryX0,
    )

    s = RegisterState()
    s.set("x1", ConstantPool(0x1234))
    s.set("x0", EntryX0)
    assert s.get("x1") == ConstantPool(0x1234)
    assert s.get("x0") is EntryX0


def test_singletons_are_distinct():
    """Each singleton marker must be a unique object."""
    from chimera.parsers.arm64_register_track import Unknown, EntryX0, Super

    assert Unknown is not EntryX0
    assert Unknown is not Super
    assert EntryX0 is not Super


def test_register_state_clobber_resets_caller_saved():
    """A `bl` to a non-msgSend target clobbers x0..x18 per AAPCS64."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, Unknown,
    )

    s = RegisterState()
    for i in range(19):
        s.set(f"x{i}", ConstantPool(0x1000 + i))
    s.set("x19", ConstantPool(0xDEAD))  # callee-saved, must survive
    s.clobber_caller_saved()
    assert s.get("x0") == Unknown
    assert s.get("x18") == Unknown
    # x19+ are callee-saved; survive
    assert s.get("x19") == ConstantPool(0xDEAD)


def test_apply_adrp_sets_constant_pool_anchor():
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, apply_instruction,
    )

    s = RegisterState()
    apply_instruction(s, {"opcode": "adrp", "operands": ["x1", 0x100200000]}, fn_offset=0x1000, insn_offset=0x1000)
    assert s.get("x1") == ConstantPool(0x100200000)


def test_apply_adrp_then_add_refines_to_full_address():
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, apply_instruction,
    )

    s = RegisterState()
    apply_instruction(s, {"opcode": "adrp", "operands": ["x1", 0x100200000]}, fn_offset=0x1000, insn_offset=0x1000)
    apply_instruction(s, {"opcode": "add", "operands": ["x1", "x1", 0x40]}, fn_offset=0x1000, insn_offset=0x1004)
    assert s.get("x1") == ConstantPool(0x100200040)


def test_apply_mov_at_function_entry_sets_entry_x0():
    """A `mov xN, x0` in the first 4 instructions captures the saved receiver."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, EntryX0, apply_instruction,
    )

    s = RegisterState()
    apply_instruction(s, {"opcode": "mov", "operands": ["x19", "x0"]}, fn_offset=0x1000, insn_offset=0x1000)
    assert s.get("x19") is EntryX0


def test_apply_mov_after_prologue_does_not_set_entry_x0():
    """Past the prologue window, mov x_, x0 is just a normal copy (Unknown)."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, Unknown, apply_instruction,
    )

    s = RegisterState()
    apply_instruction(s, {"opcode": "mov", "operands": ["x19", "x0"]}, fn_offset=0x1000, insn_offset=0x1100)
    assert s.get("x19") == Unknown


def test_apply_ret_signals_terminate():
    """ret returns the sentinel string 'ret' so the extractor can stop walking."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, apply_instruction,
    )

    s = RegisterState()
    result = apply_instruction(s, {"opcode": "ret", "operands": []}, fn_offset=0x1000, insn_offset=0x1100)
    assert result == "ret"


def test_apply_unknown_opcode_clobbers_target_register():
    """Unrecognized writes set the destination to Unknown; sources untouched."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, Unknown, apply_instruction,
    )

    s = RegisterState()
    s.set("x1", ConstantPool(0x40))
    s.set("x2", ConstantPool(0x80))
    apply_instruction(s, {"opcode": "eor", "operands": ["x1", "x2", "x3"]}, fn_offset=0x1000, insn_offset=0x1100)
    # eor first operand is the destination; x1 should now be Unknown
    assert s.get("x1") == Unknown
    # x2 is a source; unchanged
    assert s.get("x2") == ConstantPool(0x80)


def test_apply_add_with_non_matching_source_clobbers_destination():
    """`add x1, x2, 0x40` (different source) clobbers x1 to Unknown."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, Unknown, apply_instruction,
    )

    s = RegisterState()
    s.set("x1", ConstantPool(0x100))
    s.set("x2", ConstantPool(0x200))
    apply_instruction(s, {"opcode": "add", "operands": ["x1", "x2", 0x40]},
                       fn_offset=0x1000, insn_offset=0x1100)
    assert s.get("x1") == Unknown
    assert s.get("x2") == ConstantPool(0x200)


def test_apply_w_register_write_clobbers_aliased_x_register():
    """`eor w0, w1, w2` clobbers x0 (w0 is the lower 32 bits of x0)."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, Unknown, apply_instruction,
    )

    s = RegisterState()
    s.set("x0", ConstantPool(0x100200040))
    apply_instruction(s, {"opcode": "eor", "operands": ["w0", "w1", "w2"]},
                       fn_offset=0x1000, insn_offset=0x1100)
    assert s.get("x0") == Unknown


def test_apply_simd_register_write_does_not_touch_x_state():
    """`fadd q0, q1, q2` is SIMD and outside our tracking — x0 unchanged."""
    from chimera.parsers.arm64_register_track import (
        RegisterState, ConstantPool, apply_instruction,
    )

    s = RegisterState()
    s.set("x0", ConstantPool(0x100200040))
    apply_instruction(s, {"opcode": "fadd", "operands": ["q0", "q1", "q2"]},
                       fn_offset=0x1000, insn_offset=0x1100)
    assert s.get("x0") == ConstantPool(0x100200040)
