"""EVM bytecode triage: disassembly, selector recovery, and the bounded
pure-function interpreter.

Bytecode fixtures are hand-assembled here (no external solc, no challenge
coupling) so each test states exactly what it exercises. The headline test
runs a real LCG step `(a*s + c) mod m` through the interpreter and checks it
against a Python reference — that's the capability that lets an analyst verify
an on-chain formula without deploying to a testnet.
"""
from __future__ import annotations

import pytest

from chimera.parsers.evm import (
    EvmRevert,
    EvmUnsupported,
    disassemble,
    evm_tour,
    function_selectors,
    run_pure,
    split_deploy_runtime,
    strip_metadata,
)

# ── a tiny assembler so fixtures read as mnemonics ──────────────────────────
_MNE = {
    "STOP": 0x00, "ADD": 0x01, "MUL": 0x02, "SUB": 0x03, "MULMOD": 0x09,
    "ADDMOD": 0x08, "EQ": 0x14, "ISZERO": 0x15, "XOR": 0x18, "SLT": 0x12,
    "CALLDATALOAD": 0x35, "CODECOPY": 0x39, "POP": 0x50, "MLOAD": 0x51,
    "MSTORE": 0x52, "JUMP": 0x56, "JUMPI": 0x57, "JUMPDEST": 0x5B, "PUSH0": 0x5F,
    "DUP1": 0x80, "SWAP1": 0x90, "SLOAD": 0x54, "RETURN": 0xF3, "REVERT": 0xFD,
}


def asm(*ops) -> bytes:
    """('PUSH1', 0x20), 'ADD', ... -> bytes. PUSHn takes an int operand."""
    out = bytearray()
    for op in ops:
        if isinstance(op, tuple):
            name, val = op
            n = int(name[4:])                     # PUSH1..PUSH32
            out.append(0x60 + n - 1)
            out += val.to_bytes(n, "big")
        else:
            out.append(_MNE[op])
    return bytes(out)


def test_disassemble_operand_lengths():
    code = asm(("PUSH1", 0x11), ("PUSH2", 0x1234), "ADD", "STOP")
    ins = disassemble(code)
    assert [i.mnemonic for i in ins] == ["PUSH1", "PUSH2", "ADD", "STOP"]
    assert ins[0].imm_int == 0x11
    assert ins[1].imm_int == 0x1234
    assert ins[1].pc == 2                          # PUSH1 consumed 2 bytes


def test_strip_metadata_removes_cbor_trailer():
    body = asm("STOP")
    # a2 <..blob..> <len:2>  — solc metadata shape
    blob = b"\xa2\x64ipfs" + b"\x00" * 3
    code = body + blob + len(blob).to_bytes(2, "big")
    assert strip_metadata(code) == body
    assert strip_metadata(body) == body            # no trailer → unchanged


def test_split_deploy_runtime():
    runtime = asm("JUMPDEST", "STOP")
    # PUSH1 len DUP1 PUSH1 off PUSH0 CODECOPY PUSH0 RETURN  || runtime.
    # off must equal the preamble length so the runtime is copied from there.
    off = 9
    deploy = asm(("PUSH1", len(runtime)), "DUP1", ("PUSH1", off),
                 "PUSH0", "CODECOPY", "PUSH0", "RETURN")
    assert len(deploy) == off                       # runtime starts right after
    got, got_off = split_deploy_runtime(deploy + runtime)
    assert got_off == off
    assert got == runtime


def test_function_selectors():
    # DUP1 PUSH4 sel EQ PUSH2 dest JUMPI  (twice)
    code = asm("DUP1", ("PUSH4", 0x11521834), "EQ", ("PUSH2", 0x0050), "JUMPI",
               "DUP1", ("PUSH4", 0x62300756), "EQ", ("PUSH2", 0x0080), "JUMPI")
    sels = function_selectors(code)
    assert [s.selector for s in sels] == ["0x11521834", "0x62300756"]
    assert sels[0].dest == 0x50


def _lcg_step_bytecode() -> bytes:
    """Return runtime that computes (a*s + c) mod m from calldata words at
    byte offsets 0(a),32(s),64(c),96(m) and RETURNs the 32-byte result."""
    return asm(
        ("PUSH1", 96), "CALLDATALOAD",            # [m]
        ("PUSH1", 64), "CALLDATALOAD",            # [m, c]
        ("PUSH1", 96), "CALLDATALOAD",            # [m, c, m]
        ("PUSH1", 32), "CALLDATALOAD",            # [m, c, m, s]
        ("PUSH1", 0), "CALLDATALOAD",             # [m, c, m, s, a]
        "MULMOD",                                  # [m, c, (a*s)%m]
        "ADDMOD",                                  # [((a*s)%m + c)%m]
        ("PUSH1", 0), "MSTORE",
        ("PUSH1", 32), ("PUSH1", 0), "RETURN",
    )


def test_run_pure_lcg_step_matches_reference():
    a, s, c, m = 6364136223846793005, 42, 1442695040888963407, (1 << 255) - 19
    calldata = b"".join(x.to_bytes(32, "big") for x in (a, s, c, m))
    out = run_pure(_lcg_step_bytecode(), calldata)
    assert int.from_bytes(out, "big") == (a * s + c) % m


def test_run_pure_branch_via_jumpi():
    # if calldata word0 != 0 -> return 1 else return 0. The "return 1" branch
    # is a JUMPDEST appended after the fall-through block, so its pc is the
    # length of the leading block — compute that, then assemble with it.
    def build(dest: int) -> bytes:
        return asm(
            ("PUSH1", 0), "CALLDATALOAD",            # cond
            ("PUSH2", dest), "JUMPI",                # if cond -> return-1 branch
            ("PUSH1", 0), ("PUSH1", 0), "MSTORE",    # else store 0
            ("PUSH1", 32), ("PUSH1", 0), "RETURN",
        )
    one = asm("JUMPDEST", ("PUSH1", 1), ("PUSH1", 0), "MSTORE",
              ("PUSH1", 32), ("PUSH1", 0), "RETURN")
    dest = len(build(0))                              # JUMPDEST sits right after
    full = build(dest) + one
    assert int.from_bytes(run_pure(full, (5).to_bytes(32, "big")), "big") == 1
    assert int.from_bytes(run_pure(full, (0).to_bytes(32, "big")), "big") == 0


def test_run_pure_signed_ops():
    # SLT: -1 (as 2^256-1) < 1 signed  → 1;  unsigned LT would be 0.
    code = asm(("PUSH1", 1),
               ("PUSH32", (1 << 256) - 1), "SLT",   # signed(-1) < signed(1)
               ("PUSH1", 0), "MSTORE",
               ("PUSH1", 32), ("PUSH1", 0), "RETURN")
    # asm() PUSH32 wants 32 operand bytes — handled by the tuple path
    assert int.from_bytes(run_pure(code, b""), "big") == 1


def test_run_pure_rejects_state_opcode():
    with pytest.raises(EvmUnsupported):
        run_pure(asm(("PUSH1", 0), "SLOAD", "STOP"), b"")


def test_run_pure_revert_raises():
    with pytest.raises(EvmRevert):
        run_pure(asm(("PUSH1", 0), ("PUSH1", 0), "REVERT"), b"")


def test_evm_tour_on_deploy_blob():
    runtime = asm("DUP1", ("PUSH4", 0x11521834), "EQ", ("PUSH2", 0x0050),
                  "JUMPI", "STOP")
    off = 9
    deploy = asm(("PUSH1", len(runtime)), "DUP1", ("PUSH1", off),
                 "PUSH0", "CODECOPY", "PUSH0", "RETURN") + runtime
    tour = evm_tour(deploy)
    assert tour.is_deploy and tour.runtime_offset == off
    assert [s.selector for s in tour.selectors] == ["0x11521834"]
