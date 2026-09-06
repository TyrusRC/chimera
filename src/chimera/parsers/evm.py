"""EVM smart-contract bytecode triage: disassemble, recover the function
dispatch table, and (for a leaf `pure` function) execute it without a chain.

Motivation: challenges and malware increasingly stash logic in EVM bytecode
(deployed on-chain, or embedded as a hex const) so a reader without an Ethereum
node is stuck. This gives a *static* read — no node, no testnet deploy — plus a
small stack-machine interpreter that runs a `pure`/`view` leaf so you can verify
a formula by execution instead of hand-tracing opcodes.

Scope, honestly bounded: the interpreter models the stack, volatile memory, and
calldata only. It deliberately does NOT implement storage, external calls,
gas, logs, or the create/return-data machinery — a `pure` function touches none
of those. Any such opcode raises `EvmUnsupported` rather than returning a wrong
answer. That covers the common "the algorithm lives in one pure function" case
and nothing more.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── opcode table ────────────────────────────────────────────────────────────
# name only; operand length for PUSHn is derived from the opcode value.
_OPS: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
    0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0x5F: "PUSH0",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
    0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT",
    0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for _i in range(1, 33):
    _OPS[0x60 + _i - 1] = f"PUSH{_i}"
for _i in range(1, 17):
    _OPS[0x80 + _i - 1] = f"DUP{_i}"
for _i in range(1, 17):
    _OPS[0x90 + _i - 1] = f"SWAP{_i}"
for _i in range(0, 5):
    _OPS[0xA0 + _i] = f"LOG{_i}"

_UINT = (1 << 256) - 1


class EvmUnsupported(Exception):
    """An opcode the bounded pure-interpreter deliberately does not model."""


class EvmRevert(Exception):
    """The executed code hit REVERT/INVALID."""


@dataclass
class Insn:
    pc: int
    op: int
    mnemonic: str
    imm: bytes = b""            # PUSH operand bytes, else empty

    @property
    def imm_int(self) -> int | None:
        return int.from_bytes(self.imm, "big") if self.imm else None

    def __str__(self) -> str:
        if self.imm:
            return f"{self.pc:04x}: {self.mnemonic} 0x{self.imm.hex()}"
        return f"{self.pc:04x}: {self.mnemonic}"


def _to_bytes(code: str | bytes) -> bytes:
    if isinstance(code, str):
        return bytes.fromhex(code[2:] if code.startswith("0x") else code)
    return code


def strip_metadata(code: bytes) -> bytes:
    """Drop the Solidity CBOR metadata trailer if present.

    solc appends `... a2 64 'ipfs' .. 64 'solc' .. <len:2 bytes>` to runtime.
    The final two bytes are the CBOR blob length; lop it off so it doesn't
    disassemble as spurious opcodes. Returns `code` unchanged if no trailer.
    """
    if len(code) < 2:
        return code
    blob_len = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - blob_len
    # the CBOR map for solc metadata begins with 0xa2 (map of 2) / 0xa1..0xa3
    if 0 < blob_len < len(code) and code[start] in (0xA1, 0xA2, 0xA3):
        return code[:start]
    return code


def split_deploy_runtime(code: bytes) -> tuple[bytes, int]:
    """Return (runtime, offset) for constructor (deploy) bytecode.

    Deploy code ends by `CODECOPY`-ing its runtime out and `RETURN`-ing it. The
    common solc preamble is `PUSH2 len DUP1 PUSH2 off PUSH0 CODECOPY PUSH0
    RETURN` (or `PUSH1 0x00` for the older layout). We find the RETURN that
    follows a CODECOPY and read the copied region's offset/length from the
    immediately preceding pushes. If the shape isn't recognised, returns the
    whole code at offset 0 (already-runtime bytecode).
    """
    insns = disassemble(code)
    for i, ins in enumerate(insns):
        if ins.mnemonic != "CODECOPY":
            continue
        # gather the PUSH immediates just before CODECOPY: [destOff, off, len]
        pushes = [p.imm_int for p in insns[max(0, i - 6):i]
                  if p.mnemonic.startswith("PUSH") and p.imm_int is not None]
        if len(pushes) < 2:
            continue
        # solc emits DUP1 for length, so the two distinct pushes are len & off
        off = pushes[-1]
        length = pushes[-2] if len(pushes) >= 2 else None
        if off is not None and 0 < off < len(code):
            end = off + length if length and off + length <= len(code) else len(code)
            return code[off:end], off
    return code, 0


def disassemble(code: str | bytes) -> list[Insn]:
    """Linear-sweep disassembly. Unknown bytes decode as `INVALID_xx`."""
    b = _to_bytes(code)
    out: list[Insn] = []
    i = 0
    n = len(b)
    while i < n:
        op = b[i]
        name = _OPS.get(op)
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            k = op - 0x5F
            imm = b[i + 1:i + 1 + k]
            out.append(Insn(i, op, name, imm))
            i += 1 + k
        else:
            out.append(Insn(i, op, name or f"INVALID_{op:02x}"))
            i += 1
    return out


def format_disasm(insns: list[Insn]) -> str:
    return "\n".join(str(x) for x in insns)


@dataclass
class Selector:
    selector: str            # 4-byte hex, e.g. "0x11521834"
    dest: int | None         # jump target of the dispatcher branch


def function_selectors(code: str | bytes) -> list[Selector]:
    """Recover the 4-byte function selectors from the solc dispatcher.

    The dispatcher compares the top 4 bytes of calldata against each selector:
    `PUSH4 <sel> EQ PUSH2 <dest> JUMPI` (a `DUP1 PUSH4 .. EQ` variant is common
    too). We scan for PUSH4 immediately followed within a few insns by EQ, and
    grab the PUSH2 dest of the following JUMPI.
    """
    insns = disassemble(code)
    out: list[Selector] = []
    for i, ins in enumerate(insns):
        if ins.op != 0x63:  # PUSH4
            continue
        window = insns[i + 1:i + 4]
        if not any(w.mnemonic == "EQ" for w in window):
            continue
        dest = None
        for w in insns[i + 1:i + 6]:
            if w.mnemonic == "PUSH2":
                dest = w.imm_int
                break
        out.append(Selector(f"0x{ins.imm.hex()}", dest))
    # de-dup, keep first occurrence order
    seen: set[str] = set()
    uniq: list[Selector] = []
    for s in out:
        if s.selector not in seen:
            seen.add(s.selector)
            uniq.append(s)
    return uniq


# ── bounded pure-function interpreter ───────────────────────────────────────
def _signed(x: int) -> int:
    return x - (1 << 256) if x >> 255 else x


def _sdiv(a: int, b: int) -> int:
    if b == 0:
        return 0
    sa, sb = _signed(a), _signed(b)
    q = abs(sa) // abs(sb)
    return (-q if (sa < 0) != (sb < 0) else q) & _UINT


def _smod(a: int, b: int) -> int:
    if b == 0:
        return 0
    sa, sb = _signed(a), _signed(b)
    r = abs(sa) % abs(sb)              # EVM SMOD result takes the sign of `a`
    return (-r if sa < 0 else r) & _UINT


_ARITH = {
    "ADD": lambda a, b: (a + b) & _UINT,
    "MUL": lambda a, b: (a * b) & _UINT,
    "SUB": lambda a, b: (a - b) & _UINT,
    "DIV": lambda a, b: 0 if b == 0 else a // b,
    "MOD": lambda a, b: 0 if b == 0 else a % b,
    "SDIV": _sdiv,
    "SMOD": _smod,
    "EXP": lambda a, b: pow(a, b, 1 << 256),
    "LT": lambda a, b: int(a < b),
    "GT": lambda a, b: int(a > b),
    "SLT": lambda a, b: int(_signed(a) < _signed(b)),
    "SGT": lambda a, b: int(_signed(a) > _signed(b)),
    "EQ": lambda a, b: int(a == b),
    "AND": lambda a, b: a & b,
    "OR": lambda a, b: a | b,
    "XOR": lambda a, b: a ^ b,
    "SHL": lambda sh, v: (v << sh) & _UINT if sh < 256 else 0,
    "SHR": lambda sh, v: v >> sh if sh < 256 else 0,
    "SAR": lambda sh, v: (_signed(v) >> sh) & _UINT if sh < 256 else (_UINT if v >> 255 else 0),
}


@dataclass
class _Mem:
    data: bytearray = field(default_factory=bytearray)

    def _grow(self, end: int) -> None:
        if end > len(self.data):
            self.data.extend(b"\x00" * (end - len(self.data)))

    def load(self, off: int) -> int:
        self._grow(off + 32)
        return int.from_bytes(self.data[off:off + 32], "big")

    def store(self, off: int, val: int) -> None:
        self._grow(off + 32)
        self.data[off:off + 32] = val.to_bytes(32, "big")

    def store8(self, off: int, val: int) -> None:
        self._grow(off + 1)
        self.data[off] = val & 0xFF


def run_pure(code: str | bytes, calldata: bytes, *, max_steps: int = 100_000) -> bytes | None:
    """Execute EVM `code` against `calldata` as a pure function; return the
    RETURN'd bytes (or None if it STOPs with no return).

    Raises `EvmUnsupported` for any state/environment/call opcode, `EvmRevert`
    on REVERT/INVALID, and ValueError on a bad jump. Intended for a leaf
    `pure`/`view` routine: build `calldata` as selector||abi-encoded-args and
    read the decoded result.

    NOTE (ceiling): no storage, calls, gas, or logs — a pure function needs
    none. Step-bounded to guard a runaway loop.
    """
    b = strip_metadata(_to_bytes(code))
    insns = disassemble(b)
    by_pc = {ins.pc: idx for idx, ins in enumerate(insns)}
    jumpdests = {ins.pc for ins in insns if ins.mnemonic == "JUMPDEST"}

    stack: list[int] = []
    mem = _Mem()

    def pop() -> int:
        return stack.pop()

    idx = 0
    steps = 0
    while idx < len(insns):
        steps += 1
        if steps > max_steps:
            raise EvmUnsupported("step limit exceeded (possible infinite loop)")
        ins = insns[idx]
        m = ins.mnemonic

        if m.startswith("PUSH"):
            stack.append(ins.imm_int or 0)
        elif m.startswith("DUP"):
            k = int(m[3:])
            stack.append(stack[-k])
        elif m.startswith("SWAP"):
            k = int(m[4:])
            stack[-1], stack[-1 - k] = stack[-1 - k], stack[-1]
        elif m == "POP":
            pop()
        elif m in _ARITH:
            a, c = pop(), pop()
            stack.append(_ARITH[m](a, c))
        elif m == "ADDMOD":
            a, c, mod = pop(), pop(), pop()
            stack.append(0 if mod == 0 else (a + c) % mod)
        elif m == "MULMOD":
            a, c, mod = pop(), pop(), pop()
            stack.append(0 if mod == 0 else (a * c) % mod)
        elif m == "ISZERO":
            stack.append(int(pop() == 0))
        elif m == "NOT":
            stack.append((~pop()) & _UINT)
        elif m == "BYTE":
            i_, v = pop(), pop()
            stack.append((v >> (8 * (31 - i_))) & 0xFF if i_ < 32 else 0)
        elif m == "CALLDATALOAD":
            off = pop()
            word = (calldata[off:off + 32]).ljust(32, b"\x00")
            stack.append(int.from_bytes(word, "big"))
        elif m == "CALLDATASIZE":
            stack.append(len(calldata))
        elif m == "CALLVALUE":
            # We invoke as a value-less (pure/staticcall) call, so msg.value is
            # genuinely 0 — this is exactly solc's non-payable guard prologue.
            stack.append(0)
        elif m == "CALLDATACOPY":
            dst, src, ln = pop(), pop(), pop()
            chunk = calldata[src:src + ln].ljust(ln, b"\x00")
            mem._grow(dst + ln)
            mem.data[dst:dst + ln] = chunk
        elif m == "MLOAD":
            stack.append(mem.load(pop()))
        elif m == "MSTORE":
            off, val = pop(), pop()
            mem.store(off, val)
        elif m == "MSTORE8":
            off, val = pop(), pop()
            mem.store8(off, val)
        elif m == "MSIZE":
            stack.append(len(mem.data))
        elif m == "JUMP":
            dest = pop()
            if dest not in jumpdests:
                raise ValueError(f"bad jump to {dest:#x}")
            idx = by_pc[dest]
            continue
        elif m == "JUMPI":
            dest, cond = pop(), pop()
            if cond:
                if dest not in jumpdests:
                    raise ValueError(f"bad jump to {dest:#x}")
                idx = by_pc[dest]
                continue
        elif m == "JUMPDEST":
            pass
        elif m == "PC":
            stack.append(ins.pc)
        elif m == "RETURN":
            off, ln = pop(), pop()
            mem._grow(off + ln)
            return bytes(mem.data[off:off + ln])
        elif m == "STOP":
            return None
        elif m in ("REVERT", "INVALID") or m.startswith("INVALID_"):
            raise EvmRevert(f"{m} at pc {ins.pc:#x}")
        else:
            raise EvmUnsupported(f"opcode {m} at pc {ins.pc:#x} not modelled")
        idx += 1
    return None


@dataclass
class EvmTour:
    """Result of `evm_tour` — a one-shot triage of a bytecode blob."""
    size: int
    is_deploy: bool
    runtime_offset: int
    instruction_count: int
    selectors: list[Selector]
    disassembly: str
    metadata_stripped: bool

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "is_deploy": self.is_deploy,
            "runtime_offset": self.runtime_offset,
            "instruction_count": self.instruction_count,
            "selectors": [{"selector": s.selector, "dest": s.dest}
                          for s in self.selectors],
            "metadata_stripped": self.metadata_stripped,
            "disassembly": self.disassembly,
        }


def evm_tour(code: str | bytes) -> EvmTour:
    """Disassemble + recover selectors in one pass. Splits a deploy blob to its
    runtime, strips solc metadata, and lists the dispatcher's function
    selectors — the cheap first look at an unknown contract."""
    raw = _to_bytes(code)
    runtime, off = split_deploy_runtime(raw)
    stripped = strip_metadata(runtime)
    insns = disassemble(stripped)
    return EvmTour(
        size=len(raw),
        is_deploy=off > 0,
        runtime_offset=off,
        instruction_count=len(insns),
        selectors=function_selectors(stripped),
        disassembly=format_disasm(insns),
        metadata_stripped=len(stripped) != len(runtime),
    )
