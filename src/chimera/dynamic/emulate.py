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


# ── full-image PE emulation ──────────────────────────────────────────────
# emulate_function above maps only the target function's own bytes, so a call
# into an import, another function, a jump table or a .data blob hits unmapped
# memory and stops. That is the wrong shape for an *obfuscated* routine — a
# control-flow-flattened / MBA / computed-goto VM whose dispatch reads a data
# blob and whose "calls" are in-binary thunks. emulate_image maps the WHOLE
# image, stubs any call that leaves the executable sections as an immediate
# `ret` (imports/Qt/syscalls no longer halt the run), lazily backs unmapped
# accesses with zero pages, and can capture the printable strings the run
# writes (a decrypted flag/message). It is the productised form of the
# hand-built harness that cracked Flare-On 12 ch8's Qt VM.

def _ascii_runs(mem: dict[int, int], min_len: int = 5) -> list[dict]:
    """Reconstruct contiguous printable-ASCII runs from a {addr: byte} map."""
    runs, cur, start, last = [], [], None, None
    for a in sorted(mem):
        c = mem[a]
        if 0x20 <= c < 0x7f:
            if last is not None and a == last + 1:
                cur.append(c)
            else:
                if len(cur) >= min_len:
                    runs.append({"address": hex(start), "text": bytes(cur).decode("latin-1")})
                cur, start = [c], a
            last = a
        else:
            if len(cur) >= min_len:
                runs.append({"address": hex(start), "text": bytes(cur).decode("latin-1")})
            cur, last = [], None
    if len(cur) >= min_len:
        runs.append({"address": hex(start), "text": bytes(cur).decode("latin-1")})
    return runs


def emulate_image(*, sections: list[tuple[int, bytes]], entry: int,
                  exec_ranges: list[tuple[int, int]], args: tuple[int, ...] = (),
                  abi: str = "win64", this_ptr: int | None = None,
                  read_back: tuple[tuple[int, int], ...] = (),
                  stub_externs: bool = True, lazy_map: bool = True,
                  watch_ascii: bool = True, max_insns: int = 2_000_000,
                  timeout_s: int = 30) -> dict:
    """Emulate x86-64 code inside a fully mapped image.

    `sections` are (virtual_address, bytes) to map; `entry` is where to start;
    `exec_ranges` are the [lo, hi) VA spans of executable sections — a PC that
    leaves them (an import thunk, a syscall stub) is treated as a returned call
    when `stub_externs`. `abi` picks the arg registers ("win64": rcx,rdx,r8,r9;
    "sysv": rdi,rsi,rdx,rcx,r8,r9). `this_ptr`, when set, is written into the
    first arg register (a fake `this`). Returns instruction/edge counts, the
    stubbed extern targets, `read_back` regions and — with `watch_ascii` — the
    printable strings the run wrote.
    """
    if not unicorn_available():
        return _unavailable('unicorn not installed — pip install "chimera[emulate]"')
    import unicorn as U
    from unicorn import x86_const as R

    uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
    if abi == "win64":
        arg_regs = [R.UC_X86_REG_RCX, R.UC_X86_REG_RDX, R.UC_X86_REG_R8, R.UC_X86_REG_R9]
    else:
        arg_regs = [R.UC_X86_REG_RDI, R.UC_X86_REG_RSI, R.UC_X86_REG_RDX,
                    R.UC_X86_REG_RCX, R.UC_X86_REG_R8, R.UC_X86_REG_R9]

    mapped: set[int] = set()

    def _ensure(addr: int, size: int = 1) -> None:
        lo = _align_down(addr)
        hi = (addr + size + _PAGE - 1) & ~(_PAGE - 1)
        for p in range(lo, hi, _PAGE):
            if p not in mapped:
                try:
                    uc.mem_map(p, _PAGE)
                    mapped.add(p)
                except U.UcError:
                    pass

    for va, data in sections:
        _ensure(va, len(data))
        try:
            uc.mem_write(va, bytes(data))
        except U.UcError:
            pass

    stack_base, stack_size = 0x200000, 0x400000
    _ensure(stack_base, stack_size)
    rsp = stack_base + stack_size - 0x1000
    if this_ptr is not None:
        _ensure(this_ptr, 0x200000)
        for off in range(0, 0x200000, 8):     # self-pointers so deref chains resolve
            try:
                uc.mem_write(this_ptr + off, (this_ptr + 0x1000).to_bytes(8, "little"))
            except U.UcError:
                break
    sentinel = 0xDEAD0000
    _ensure(sentinel)
    uc.reg_write(R.UC_X86_REG_RSP, rsp)
    uc.mem_write(rsp, sentinel.to_bytes(8, "little"))
    for reg, val in zip(arg_regs, args):
        uc.reg_write(reg, int(val) & 0xFFFFFFFFFFFFFFFF)
    if this_ptr is not None:
        uc.reg_write(arg_regs[0], this_ptr)

    def _in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in exec_ranges)

    state = {"count": 0, "prev_end": 0, "edges": 0, "externs": []}

    def _code(uc_, address, size, user):
        state["count"] += 1
        pe = state["prev_end"]
        if pe and address != pe:
            state["edges"] += 1
        state["prev_end"] = address + size
        if stub_externs and not _in_exec(address):
            if address == sentinel:
                uc_.emu_stop(); return
            sp = uc_.reg_read(R.UC_X86_REG_RSP)
            try:
                ra = int.from_bytes(uc_.mem_read(sp, 8), "little")
            except U.UcError:
                uc_.emu_stop(); return
            uc_.reg_write(R.UC_X86_REG_RSP, sp + 8)
            uc_.reg_write(R.UC_X86_REG_RIP, ra)
            uc_.reg_write(R.UC_X86_REG_RAX, 0)
            if len(state["externs"]) < 256:
                state["externs"].append(hex(address))

    def _unmapped(uc_, access, address, size, value, user):
        if lazy_map:
            _ensure(address, size)
            return True
        return False

    writes: dict[int, int] = {}

    def _write(uc_, access, address, size, value, user):
        if watch_ascii and 1 <= size <= 8:
            b = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
            for i, c in enumerate(b):
                if 0x20 <= c < 0x7f:
                    writes[address + i] = c

    uc.hook_add(U.UC_HOOK_CODE, _code)
    uc.hook_add(U.UC_HOOK_MEM_READ_UNMAPPED | U.UC_HOOK_MEM_WRITE_UNMAPPED
                | U.UC_HOOK_MEM_FETCH_UNMAPPED, _unmapped)
    if watch_ascii:
        uc.hook_add(U.UC_HOOK_MEM_WRITE, _write)

    error = None
    try:
        uc.emu_start(entry, sentinel, timeout=timeout_s * 1_000_000, count=max_insns)
    except U.UcError as exc:
        error = f"{exc} at rip={hex(uc.reg_read(R.UC_X86_REG_RIP))}"
    except Exception as exc:  # pragma: no cover - defensive
        error = f"{type(exc).__name__}: {exc}"

    returned = uc.reg_read(R.UC_X86_REG_RIP) == sentinel
    read_out = []
    for addr, length in read_back:
        try:
            data = uc.mem_read(addr, length)
            read_out.append({"address": hex(addr), "hex": bytes(data).hex(),
                             "ascii": bytes(data).decode("latin-1")})
        except Exception:
            read_out.append({"address": hex(addr), "error": "unreadable"})

    return {"available": True, "ok": error is None and returned, "returned": returned,
            "error": error, "instructions": state["count"], "edges": state["edges"],
            "return_value": uc.reg_read(R.UC_X86_REG_RAX),
            "extern_calls": state["externs"], "read_back": read_out,
            "ascii_writes": _ascii_runs(writes) if watch_ascii else []}


def emulate_pe_function(path: str, address: int | str, *, args: tuple[int, ...] = (),
                        this_ptr: int | None = 0x10000000,
                        read_back: tuple[tuple[int, int], ...] = (),
                        stub_externs: bool = True, lazy_map: bool = True,
                        watch_ascii: bool = True, max_insns: int = 2_000_000,
                        timeout_s: int = 30) -> dict:
    """Map an entire PE and emulate the function at `address` (x86-64, MS ABI).

    The full-image counterpart of emulate_function for obfuscated Windows code
    (a computed-goto / MBA VM): every section is mapped at its ImageBase so
    intra-binary thunks, jump tables and data blobs resolve; calls that leave
    the executable sections are stubbed; unmapped accesses are lazily backed.
    `this_ptr` seeds a fake `this` object in the first (rcx) argument. Needs
    `pefile` and the `emulate` extra.
    """
    if not unicorn_available():
        return _unavailable('unicorn not installed — pip install "chimera[emulate]"')
    try:
        import pefile  # noqa: PLC0415
    except Exception:
        return _unavailable("pefile not installed — required for PE emulation")

    va = int(address, 16) if isinstance(address, str) else int(address)
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception as exc:
        return _unavailable(f"could not parse PE {path!r}: {exc}")
    if pe.FILE_HEADER.Machine != 0x8664:
        return _unavailable("only x86-64 PEs are supported")

    base = pe.OPTIONAL_HEADER.ImageBase
    raw = pe.__data__
    sections: list[tuple[int, bytes]] = [(base, bytes(raw[:0x400]))]
    exec_ranges: list[tuple[int, int]] = []
    for s in pe.sections:
        sva = base + s.VirtualAddress
        data = bytes(raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
        sections.append((sva, data))
        if s.Characteristics & 0x20000000:   # IMAGE_SCN_MEM_EXECUTE
            end = sva + max(s.Misc_VirtualSize, s.SizeOfRawData)
            exec_ranges.append((sva, end))
    if not exec_ranges:
        return _unavailable("no executable section found")

    return emulate_image(sections=sections, entry=va, exec_ranges=exec_ranges,
                         args=args, abi="win64", this_ptr=this_ptr,
                         read_back=read_back, stub_externs=stub_externs,
                         lazy_map=lazy_map, watch_ascii=watch_ascii,
                         max_insns=max_insns, timeout_s=timeout_s)
