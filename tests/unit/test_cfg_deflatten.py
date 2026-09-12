"""CFG-deflattener liveness backtrack (the novel bit that finds a block's footer).

Given a block ending in `jmp rax`, liveness_footer must walk back to the first
instruction of the expression that computes rax — not further. Here the footer
is the last two instructions (`mov rax,[rip+..] ; add rax, rcx`), and the code
before it (an unrelated `xor edx,edx`) must be excluded.
"""
import pytest

capstone = pytest.importorskip("capstone")
from chimera.parsers.cfg_deflatten import liveness_footer, _normalize, _PARENT


def _disasm(hexstr, base=0x1000):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return list(md.disasm(bytes.fromhex(hexstr), base))


def test_liveness_finds_footer_start_unconditional():
    # 31d2            xor edx, edx        (unrelated — must be EXCLUDED)
    # 48c7c105000000  mov rcx, 5          (footer start: defines rcx)
    # 488b0500000000  mov rax, [rip+0]    (footer: defines rax from memory)
    # 4801c8          add rax, rcx        (footer: rax += rcx)
    # ffe0            jmp rax
    insns = _disasm("31d2" "48c7c105000000" "488b0500000000" "4801c8" "ffe0")
    idx, cond = liveness_footer(insns, "rax")
    assert cond == "uncond"
    # footer is self-contained from `mov rcx, 5` (index 1); the xor (0) is excluded
    assert idx == 1 and insns[idx].mnemonic == "mov"


def test_liveness_detects_setz_conditional():
    # 4839c8    cmp rax, rcx
    # 0f94c0    sete al        (SETZ -> conditional footer)
    # 4863c0    movsxd rax, eax
    # ffe0      jmp rax
    insns = _disasm("4839c8" "0f94c0" "4863c0" "ffe0")
    _idx, cond = liveness_footer(insns, "rax")
    assert cond == "setz"


def test_register_normalization_folds_subregisters():
    assert _normalize(["eax", "al", "rax"]) == {"rax"}
    assert _PARENT["r9d"] == "r9"
