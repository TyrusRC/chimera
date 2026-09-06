"""Emulate one function in isolation — deobfuscate without running the whole binary.

A hash resolver, a string-decrypt routine, a checksum: these are leaf
functions whose *output* is what an analyst wants, and static reading of
an obfuscated one is slow and error-prone. This runs just that function
under Unicorn with chosen arguments and reads back the result — the
"emulate_function / emulate_hash_batch" capability the Ghidra MCP servers
expose, on chimera's side and cross-format via `BinaryPatcher` byte reads.

NOTE (ceiling): this maps only the function's own bytes plus a stack. A
call into an import or a syscall hits unmapped memory and stops the run —
by design, it targets self-contained routines. Handling PLT/IAT calls and
syscalls is the upgrade path (map stubs, or hook UC_HOOK_MEM_UNMAPPED).
Unicorn is optional (`pip install "chimera[emulate]"`); absent, every
entry point degrades to an ``available: False`` result.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_PAGE = 0x1000
_CODE_BASE = 0x00400000
_STACK_BASE = 0x00B00000        # distinct from code + sentinel; 64 KiB
_STACK_SIZE = 0x00010000
_SENTINEL = 0x00CAFE00          # return target: PC reaching here ends the run

# The two architectures chimera cares about for this: desktop x86-64 and
# mobile/native arm64. Others degrade to an explicit "unsupported" error.
_SUPPORTED = ("x86_64", "arm64")


def unicorn_available() -> bool:
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def _align_down(x: int) -> int:
    return x & ~(_PAGE - 1)


def _map_region(uc, addr: int, size: int) -> None:
    start = _align_down(addr)
    end = (addr + size + _PAGE - 1) & ~(_PAGE - 1)
    uc.mem_map(start, end - start)


def _unavailable(reason: str) -> dict:
    return {"available": False, "ok": False, "error": reason, "return_value": None,
            "instructions": 0, "read_back": []}


def emulate_code(code: bytes, *, arch: str, base: int = _CODE_BASE,
                 args: tuple[int, ...] = (), mem: tuple[tuple[int, bytes], ...] = (),
                 read_back: tuple[tuple[int, int], ...] = (),
                 max_insns: int = 200_000, timeout_s: int = 5) -> dict:
    """Run raw machine `code` for `arch` with integer `args`, return the result.

    `mem` places byte buffers at addresses before the run (an input buffer
    an argument points at); `read_back` names (addr, length) regions to
    return after it (a decrypt routine's output). Stops at the return
    sentinel, the instruction cap, or a fault — reporting which.
    """
    if arch not in _SUPPORTED:
        return _unavailable(f"unsupported arch {arch!r}; supported: {_SUPPORTED}")
    if not unicorn_available():
        return _unavailable("unicorn not installed — pip install \"chimera[emulate]\"")

    import unicorn as U
    if arch == "x86_64":
        from unicorn import x86_const as R
        uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        arg_regs = [R.UC_X86_REG_RDI, R.UC_X86_REG_RSI, R.UC_X86_REG_RDX,
                    R.UC_X86_REG_RCX, R.UC_X86_REG_R8, R.UC_X86_REG_R9]
        sp_reg, ret_reg, pc_reg = R.UC_X86_REG_RSP, R.UC_X86_REG_RAX, R.UC_X86_REG_RIP
    else:  # arm64
        from unicorn import arm64_const as R
        uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
        arg_regs = [R.UC_ARM64_REG_X0, R.UC_ARM64_REG_X1, R.UC_ARM64_REG_X2,
                    R.UC_ARM64_REG_X3, R.UC_ARM64_REG_X4, R.UC_ARM64_REG_X5,
                    R.UC_ARM64_REG_X6, R.UC_ARM64_REG_X7]
        sp_reg, ret_reg, pc_reg = R.UC_ARM64_REG_SP, R.UC_ARM64_REG_X0, R.UC_ARM64_REG_PC
        lr_reg = R.UC_ARM64_REG_LR

    _map_region(uc, base, len(code))
    uc.mem_write(base, bytes(code))
    _map_region(uc, _STACK_BASE, _STACK_SIZE)
    _map_region(uc, _SENTINEL, _PAGE)          # so PC can land on the stop target
    for addr, buf in mem:
        _map_region(uc, addr, len(buf))
        uc.mem_write(addr, bytes(buf))

    sp = _STACK_BASE + _STACK_SIZE // 2
    if arch == "x86_64":
        sp -= 8
        uc.reg_write(sp_reg, sp)
        uc.mem_write(sp, _SENTINEL.to_bytes(8, "little"))   # `ret` -> sentinel
    else:
        uc.reg_write(sp_reg, sp)
        uc.reg_write(lr_reg, _SENTINEL)                     # `ret` (br lr) -> sentinel
    for reg, val in zip(arg_regs, args):
        uc.reg_write(reg, int(val) & 0xFFFFFFFFFFFFFFFF)

    state = {"count": 0}

    def _hook(uc_, address, size, user):
        state["count"] += 1
        if state["count"] > max_insns:
            uc_.emu_stop()
    uc.hook_add(U.UC_HOOK_CODE, _hook)

    error = None
    try:
        uc.emu_start(base, _SENTINEL, timeout=timeout_s * 1_000_000, count=max_insns)
    except U.UcError as exc:
        error = f"{exc}"
    except Exception as exc:  # pragma: no cover - defensive
        error = f"{type(exc).__name__}: {exc}"

    # "ok" means the function ran to its own `ret` (PC reached the sentinel),
    # not merely "no exception" — a cap/timeout stop is incomplete, not success.
    returned = uc.reg_read(pc_reg) == _SENTINEL
    if error is None and not returned:
        error = f"stopped before return after {state['count']} instructions (cap/timeout)"
    ret_val = uc.reg_read(ret_reg)
    read_out = []
    for addr, length in read_back:
        try:
            data = uc.mem_read(addr, length)
            read_out.append({"address": hex(addr), "hex": bytes(data).hex(),
                             "ascii": bytes(data).decode("latin-1")})
        except Exception:
            read_out.append({"address": hex(addr), "error": "unreadable"})

    return {"available": True, "ok": error is None and returned, "returned": returned,
            "error": error, "return_value": ret_val, "return_hex": hex(ret_val),
            "instructions": state["count"], "read_back": read_out}


def emulate_function(binary_path: str, address: int | str, *, arch: str,
                     args: tuple[int, ...] = (),
                     read_back: tuple[tuple[int, int], ...] = (),
                     code_window: int = 0x800, max_insns: int = 200_000) -> dict:
    """Read the function's bytes at `address` from the binary and emulate them.

    Reads a fixed window (execution stops at the function's own `ret`, so
    over-reading past it is harmless). Cross-format via BinaryPatcher's
    VA→offset. `address` accepts int or hex string.
    """
    if not unicorn_available():
        return _unavailable("unicorn not installed — pip install \"chimera[emulate]\"")
    from chimera.patching.binary_patcher import BinaryPatcher, PatchError

    va = int(address, 16) if isinstance(address, str) else int(address)
    try:
        patcher = BinaryPatcher.open(binary_path)
        code = patcher.read(va, code_window)
    except (PatchError, OSError, ValueError) as exc:
        return _unavailable(f"could not read code at {hex(va)}: {exc}")
    if not code:
        return _unavailable(f"no bytes at {hex(va)}")
    return emulate_code(code, arch=arch, base=va, args=args,
                        read_back=read_back, max_insns=max_insns)
