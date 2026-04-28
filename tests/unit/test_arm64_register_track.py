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
