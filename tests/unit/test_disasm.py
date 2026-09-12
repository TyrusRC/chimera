"""Instruction sizing + NOP fill (capstone) — the auto-sizing behind patch --nop."""
from __future__ import annotations

import pytest

from chimera.patching.disasm import DisasmError, instruction_span, nop_fill


def test_instruction_span_sizes_near_and_short_jumps():
    # near jne (0F 85 + rel32 = 6 bytes) then short je (74 + rel8 = 2 bytes)
    code = bytes.fromhex("0f85aabbccdd" "7405")
    span, texts = instruction_span(code, "x86", 0x401486, 2)
    assert span == 8
    assert texts[0].startswith("jne") and texts[1].startswith("je")


def test_instruction_span_single_near_jump_is_six_bytes():
    span, _ = instruction_span(bytes.fromhex("0f85aabbccdd"), "x86", 0x401486, 1)
    assert span == 6  # the exact case hand-counting gets wrong (looks like a short jump)


def test_instruction_span_refuses_partial_instruction():
    with pytest.raises(DisasmError):
        instruction_span(b"\x0f\x85\x00", "x86", 0, 1)  # truncated near jmp, cannot size


def test_nop_fill_x86_is_byte_granular():
    assert nop_fill("x86_64", 6) == b"\x90" * 6
    assert nop_fill("x86", 1) == b"\x90"


def test_nop_fill_fixed_width_arch_must_align():
    assert nop_fill("arm64", 8) == bytes.fromhex("1f2003d5") * 2
    assert nop_fill("thumb", 4) == bytes.fromhex("00bf") * 2
    with pytest.raises(DisasmError):
        nop_fill("arm64", 6)  # not a multiple of the 4-byte ARM64 NOP


def test_nop_fill_unknown_arch():
    with pytest.raises(DisasmError):
        nop_fill("mips", 4)
