"""Recover the real control-flow graph of a computed-goto / MBA-obfuscated function.

Flattening compilers (and hand-rolled VM obfuscators, such as a Qt GUI
authenticator) replace every branch with a block that *computes* its successor
address into a register via MBA arithmetic + data-blob reads and ends in a bare
`jmp rax`. A linear disassembler sees one giant basic block with an opaque
indirect jump; the true edges are invisible.

This recovers them the way the official ch8 write-up did with a Ghidra script,
but with capstone + unicorn and no Ghidra:

  1. Disassemble a block linearly until its terminator.
  2. For a computed `jmp reg`, walk backwards doing liveness on the GP registers
     — treat the jump register as unaccounted, and for each earlier instruction
     remove what it defines and add what it reads, until nothing is unaccounted.
     That start is the "footer expression" that computes the target.
  3. Emulate the footer (whole image mapped, so its blob reads resolve) and read
     the jump register = the successor. A conditional footer (SETZ/SETNZ/SETGE,
     or a bare SUB) is emulated once per flag value to recover both edges.
  4. BFS over successors to build the CFG.

Read-only; needs capstone and the `emulate` extra (unicorn + pefile).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# capstone/unicorn are optional — degrade to an explicit unavailable result.
def _deps_ok() -> bool:
    try:
        import capstone, unicorn  # noqa: F401,PLC0415
        return True
    except Exception:
        return False


# GP register name -> 64-bit parent, so liveness treats AL/EAX/RAX as one.
_PARENT = {}
def _build_parent_map():
    fam = {
        "rax": ["rax", "eax", "ax", "al", "ah"],
        "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
        "rcx": ["rcx", "ecx", "cx", "cl", "ch"],
        "rdx": ["rdx", "edx", "dx", "dl", "dh"],
        "rsi": ["rsi", "esi", "si", "sil"],
        "rdi": ["rdi", "edi", "di", "dil"],
        "rbp": ["rbp", "ebp", "bp", "bpl"],
        "rsp": ["rsp", "esp", "sp", "spl"],
    }
    for i in range(8, 16):
        fam[f"r{i}"] = [f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"]
    for parent, kids in fam.items():
        for k in kids:
            _PARENT[k] = parent
_build_parent_map()


def _normalize(regnames):
    return {_PARENT[n] for n in regnames if n in _PARENT}


def liveness_footer(insns, jmp_reg: str) -> tuple[int, str]:
    """Backtrack over a block's capstone `insns` to the start of the expression
    that computes `jmp_reg`, and classify a nearby conditional (setz/setnz/setge).

    Returns (start_index, condition). Treats the jump register as unaccounted;
    each earlier instruction removes what it writes and adds what it reads,
    until nothing is unaccounted — that instruction begins the footer.
    """
    unaccounted = {_PARENT.get(jmp_reg, jmp_reg)}
    start_idx = 0
    for i in range(len(insns) - 1, -1, -1):
        ins = insns[i]
        rd, wr = ins.regs_access()
        unaccounted -= _normalize(ins.reg_name(r) for r in wr)
        unaccounted |= _normalize(ins.reg_name(r) for r in rd)
        if not unaccounted:
            start_idx = i
            break
    cond = "uncond"
    for ins in insns[max(0, start_idx - 2):start_idx + 4]:
        m = ins.mnemonic
        if m in ("sete", "setz"):
            cond = "setz"; break
        if m in ("setne", "setnz"):
            cond = "setnz"; break
        if m == "setge":
            cond = "setge"; break
    return start_idx, cond


def recover_cfg(path: str, entry: int | str, *, max_blocks: int = 4000,
                max_footer_insns: int = 400, max_block_insns: int = 4000) -> dict:
    """Recover the CFG of the function at `entry`. Returns blocks, edges, stats."""
    if not _deps_ok():
        return {"available": False,
                "error": 'needs capstone + the "emulate" extra (unicorn, pefile)'}
    import capstone as C
    import unicorn as U
    from unicorn import x86_const as UR
    from chimera.dynamic.emulate_image import pe_image_sections

    entry = int(entry, 16) if isinstance(entry, str) else int(entry)
    try:
        _base, sections, exec_ranges = pe_image_sections(path)
    except ValueError as exc:
        return {"available": False, "error": str(exc)}

    # index section bytes by VA for the linear disassembler
    def read_va(va: int, n: int) -> bytes:
        for sva, data in sections:
            if sva <= va < sva + len(data):
                off = va - sva
                return data[off:off + n]
        return b""

    def in_exec(va: int) -> bool:
        return any(lo <= va < hi for lo, hi in exec_ranges)

    md = C.Cs(C.CS_ARCH_X86, C.CS_MODE_64)
    md.detail = True

    # one unicorn image for footer emulation; regs/stack reset per footer
    uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
    mapped: set[int] = set()

    def ensure(addr, size=1):
        lo = addr & ~0xFFF
        hi = (addr + size + 0xFFF) & ~0xFFF
        for p in range(lo, hi, 0x1000):
            if p not in mapped:
                try:
                    uc.mem_map(p, 0x1000); mapped.add(p)
                except U.UcError:
                    pass
    for sva, data in sections:
        ensure(sva, len(data))
        try:
            uc.mem_write(sva, data)
        except U.UcError:
            pass
    STACK, SSIZE = 0x300000, 0x200000
    ensure(STACK, SSIZE)
    uc.hook_add(U.UC_HOOK_MEM_READ_UNMAPPED | U.UC_HOOK_MEM_WRITE_UNMAPPED
                | U.UC_HOOK_MEM_FETCH_UNMAPPED,
                lambda uc_, a, addr, sz, v, u: (ensure(addr, sz), True)[1])

    GP = [UR.UC_X86_REG_RAX, UR.UC_X86_REG_RBX, UR.UC_X86_REG_RCX, UR.UC_X86_REG_RDX,
          UR.UC_X86_REG_RSI, UR.UC_X86_REG_RDI, UR.UC_X86_REG_R8, UR.UC_X86_REG_R9,
          UR.UC_X86_REG_R10, UR.UC_X86_REG_R11, UR.UC_X86_REG_R12, UR.UC_X86_REG_R13,
          UR.UC_X86_REG_R14, UR.UC_X86_REG_R15]
    REG_BY_NAME = {"rax": UR.UC_X86_REG_RAX, "rbx": UR.UC_X86_REG_RBX,
                   "rcx": UR.UC_X86_REG_RCX, "rdx": UR.UC_X86_REG_RDX,
                   "rsi": UR.UC_X86_REG_RSI, "rdi": UR.UC_X86_REG_RDI,
                   "rbp": UR.UC_X86_REG_RBP, "rsp": UR.UC_X86_REG_RSP,
                   **{f"r{i}": getattr(UR, f"UC_X86_REG_R{i}") for i in range(8, 16)}}

    def emulate_footer(start: int, jmp_addr: int, jmp_reg: str, eflags: int | None):
        for r in GP:
            uc.reg_write(r, 0)
        uc.reg_write(UR.UC_X86_REG_RBP, STACK + SSIZE // 2)
        uc.reg_write(UR.UC_X86_REG_RSP, STACK + SSIZE // 2)
        try:                                   # clear scratch stack
            uc.mem_write(STACK, b"\x00" * SSIZE)
        except U.UcError:
            pass
        if eflags is not None:
            uc.reg_write(UR.UC_X86_REG_EFLAGS, eflags)
        try:
            uc.emu_start(start, jmp_addr, count=max_footer_insns)
        except U.UcError:
            return None
        if uc.reg_read(UR.UC_X86_REG_RIP) != jmp_addr:
            return None
        return uc.reg_read(REG_BY_NAME.get(jmp_reg, UR.UC_X86_REG_RAX))

    ZF, SF = 1 << 6, 1 << 7
    BASE_FLAGS = 0x202

    def disasm_block(start: int):
        """Linear-disasm one block; return (insns, terminator_dict)."""
        insns, va = [], start
        for _ in range(max_block_insns):
            code = read_va(va, 16)
            if not code:
                return insns, {"kind": "bad", "addr": va}
            try:
                ins = next(md.disasm(code, va))
            except StopIteration:
                return insns, {"kind": "bad", "addr": va}
            insns.append(ins)
            g = set(ins.groups)
            if C.CS_GRP_RET in g:
                return insns, {"kind": "ret", "addr": ins.address}
            if C.CS_GRP_JUMP in g:
                op = ins.operands[0]
                if op.type == C.CS_OP_IMM:
                    kind = "jcc" if ins.mnemonic != "jmp" else "jmp"
                    return insns, {"kind": kind, "addr": ins.address, "target": op.imm,
                                   "fallthrough": ins.address + ins.size}
                if op.type == C.CS_OP_REG:
                    return insns, {"kind": "jmpreg", "addr": ins.address,
                                   "reg": ins.reg_name(op.reg)}
                return insns, {"kind": "jmpmem", "addr": ins.address}
            va += ins.size
        return insns, {"kind": "toolong", "addr": va}

    blocks: dict[int, dict] = {}
    edges: set[tuple[int, int]] = set()
    unresolved = 0
    queue = [entry]
    seen: set[int] = set()
    while queue and len(blocks) < max_blocks:
        start = queue.pop()
        if start in seen or not in_exec(start):
            continue
        seen.add(start)
        insns, term = disasm_block(start)
        if not insns:
            continue
        calls = [ins.operands[0].imm for ins in insns
                 if C.CS_GRP_CALL in set(ins.groups)
                 and ins.operands and ins.operands[0].type == C.CS_OP_IMM]
        succ: list[int] = []
        if term["kind"] == "jmp":
            succ = [term["target"]]
        elif term["kind"] == "jcc":
            succ = [term["target"], term["fallthrough"]]
        elif term["kind"] == "jmpreg":
            fidx, cond = liveness_footer(insns, term["reg"])
            fstart = insns[fidx].address
            variants = ([None] if cond == "uncond"
                        else [BASE_FLAGS, BASE_FLAGS | ZF] if cond in ("setz", "setnz")
                        else [BASE_FLAGS, BASE_FLAGS | SF])   # setge: SF vs SF==OF(0)
            targets = []
            for fl in variants:
                t = emulate_footer(fstart, term["addr"], term["reg"], fl)
                if t is not None and in_exec(t):
                    targets.append(t)
            succ = sorted(set(targets))
            if not succ:
                unresolved += 1
        blocks[start] = {"start": hex(start), "end": hex(term["addr"]),
                         "term": term["kind"], "insns": len(insns),
                         "calls": [hex(c) for c in calls],
                         "successors": [hex(s) for s in succ]}
        for s in succ:
            edges.add((start, s))
            if s not in seen:
                queue.append(s)

    dot = _to_dot(entry, blocks, edges)
    return {"available": True, "entry": hex(entry), "block_count": len(blocks),
            "edge_count": len(edges), "unresolved_jmpreg": unresolved,
            "blocks": list(blocks.values()),
            "edges": [[hex(a), hex(b)] for a, b in sorted(edges)], "dot": dot}


def _to_dot(entry, blocks, edges) -> str:
    lines = ["digraph cfg {", '  node [shape=box fontname="monospace"];']
    for b in blocks.values():
        label = f'{b["start"]}\\n{b["term"]} ({b["insns"]} insns)'
        extra = ' style=filled fillcolor="#cde"' if b["start"] == hex(entry) else ""
        lines.append(f'  "{b["start"]}" [label="{label}"{extra}];')
    for a, d in sorted(edges):
        lines.append(f'  "{hex(a)}" -> "{hex(d)}";')
    lines.append("}")
    return "\n".join(lines)
