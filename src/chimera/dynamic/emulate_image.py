"""Full-image PE emulation — the counterpart to emulate.py's leaf-function runner.

emulate_function (emulate.py) maps only the target function's own bytes, so a
call into an import, another function, a jump table or a .data blob hits
unmapped memory and stops — the wrong shape for an obfuscated computed-goto /
MBA VM. This module maps the WHOLE image, stubs external calls, lazily backs
faults and captures printable writes. Split out of emulate.py to keep each
module under one responsibility.
"""
from __future__ import annotations

import logging

from chimera.dynamic.emulate import _align_down, _unavailable, unicorn_available

logger = logging.getLogger(__name__)

_PAGE = 0x1000

def pe_image_sections(path: str):
    """Parse a PE into (image_base, [(va, bytes)…], [(exec_lo, exec_hi)…]).

    Shared by the full-image emulator and the CFG deflattener. Raises
    ValueError (never pefile internals) on a non-PE / non-x86-64 / no-code file.
    """
    try:
        import pefile  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover
        raise ValueError("pefile not installed — required for PE emulation") from exc
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception as exc:
        raise ValueError(f"could not parse PE {path!r}: {exc}") from exc
    if pe.FILE_HEADER.Machine != 0x8664:
        raise ValueError("only x86-64 PEs are supported")
    base = pe.OPTIONAL_HEADER.ImageBase
    raw = pe.__data__
    sections: list[tuple[int, bytes]] = [(base, bytes(raw[:0x400]))]
    exec_ranges: list[tuple[int, int]] = []
    for s in pe.sections:
        sva = base + s.VirtualAddress
        data = bytes(raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
        sections.append((sva, data))
        if s.Characteristics & 0x20000000:   # IMAGE_SCN_MEM_EXECUTE
            exec_ranges.append((sva, sva + max(s.Misc_VirtualSize, s.SizeOfRawData)))
    if not exec_ranges:
        raise ValueError("no executable section found")
    return base, sections, exec_ranges


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
        base, sections, exec_ranges = pe_image_sections(str(path))
    except ValueError as exc:
        return _unavailable(str(exc))

    return emulate_image(sections=sections, entry=va, exec_ranges=exec_ranges,
                         args=args, abi="win64", this_ptr=this_ptr,
                         read_back=read_back, stub_externs=stub_externs,
                         lazy_map=lazy_map, watch_ascii=watch_ascii,
                         max_insns=max_insns, timeout_s=timeout_s)
