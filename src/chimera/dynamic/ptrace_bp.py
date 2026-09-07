"""Breakpoint-and-dump for a launched x86-64 process, via ptrace, with no sudo.

The gap this closes: when a target computes a secret at runtime — an AES key
derived/decrypted behind obfuscation, a password check, a value that never
appears as a literal — static disassembly can name the routine but not read the
value. You want to stop at that routine and read a register (and the memory it
points at). That is a breakpoint.

The no-sudo insight: `kernel.yama.ptrace_scope=1` blocks *attaching* to a process
that isn't your descendant, but it never blocks tracing a child you launched
under `PTRACE_TRACEME`. So we fork, have the child trace itself and exec the
target, and the parent drives software breakpoints (`int3`/0xCC). This works for
a native ELF crackme directly, and for a Windows PE run under Wine (the Wine
loader is our child, and `PTRACE_O_TRACECLONE` follows the thread the real code
runs on).

Ceilings, stated honestly:
- x86-64 Linux only.
- Software breakpoints are armed at launch. For a native ELF the .text is mapped
  at exec, so an address in the main image is armable immediately. For code that
  is mapped *later* (a PE mapped by the Wine loader, a dlopen'd/JIT'd region) the
  address isn't present at the exec-stop — arming it then fails. The caller must
  arm after the module is mapped (a future enhancement: a deferred breakpoint on
  an mmap/module-load event); this primitive keeps to the simple case.
- No hardware/watchpoints, no self-modifying-code re-sync beyond single-stepping
  over our own 0xCC.
"""
from __future__ import annotations

import ctypes
import logging
import os
import platform
import signal
import threading

logger = logging.getLogger(__name__)

# ptrace requests
_TRACEME = 0
_PEEKTEXT = 1
_POKETEXT = 4
_CONT = 7
_SINGLESTEP = 9
_GETREGS = 12
_SETREGS = 13
_SETOPTIONS = 0x4200
# option bits
_O_EXITKILL = 0x00100000
_O_TRACECLONE = 0x00000008
_O_TRACEFORK = 0x00000002
_O_TRACEVFORK = 0x00000004
_O_TRACEEXEC = 0x00000010
_OPTIONS = _O_EXITKILL | _O_TRACECLONE | _O_TRACEFORK | _O_TRACEVFORK | _O_TRACEEXEC
_WALL = 0x40000000

# user_regs_struct field order for x86-64 Linux (all unsigned long long).
_REG_FIELDS = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]
# registers a caller may name as a pointer to dump / read back
_PUBLIC_REGS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")


class UserRegs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in _REG_FIELDS]


class PtraceUnsupported(Exception):
    """ptrace breakpointing is not available in this environment."""


def _is_x86_64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")


def _libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                            ctypes.c_void_p, ctypes.c_void_p]
    libc.waitpid.restype = ctypes.c_int
    libc.waitpid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int),
                             ctypes.c_int]
    return libc


def _ptrace(libc, request, pid, addr, data):
    ctypes.set_errno(0)
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr),
                      ctypes.c_void_p(data))
    err = ctypes.get_errno()
    if res == -1 and err != 0:
        raise OSError(err, os.strerror(err), f"ptrace({request})")
    return res


def _getregs(libc, pid) -> UserRegs:
    regs = UserRegs()
    _ptrace(libc, _GETREGS, pid, 0, ctypes.cast(ctypes.byref(regs),
                                                ctypes.c_void_p).value)
    return regs


def _setregs(libc, pid, regs: UserRegs) -> None:
    _ptrace(libc, _SETREGS, pid, 0, ctypes.cast(ctypes.byref(regs),
                                                ctypes.c_void_p).value)


def _read_mem(pid: int, addr: int, length: int) -> bytes:
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as fh:
            fh.seek(addr)
            return fh.read(length)
    except (OSError, ValueError, OverflowError):
        return b""


def _set_byte_cc(libc, pid, addr, originals: dict) -> None:
    """Arm a software breakpoint at addr, remembering the original byte."""
    aligned = addr & ~0x7
    word = _ptrace(libc, _PEEKTEXT, pid, aligned, 0) & 0xFFFFFFFFFFFFFFFF
    shift = (addr - aligned) * 8
    originals[addr] = (word >> shift) & 0xFF
    patched = (word & ~(0xFF << shift)) | (0xCC << shift)
    _ptrace(libc, _POKETEXT, pid, aligned, patched)


def _restore_byte(libc, pid, addr, originals: dict) -> None:
    aligned = addr & ~0x7
    word = _ptrace(libc, _PEEKTEXT, pid, aligned, 0) & 0xFFFFFFFFFFFFFFFF
    shift = (addr - aligned) * 8
    orig = originals[addr]
    word = (word & ~(0xFF << shift)) | (orig << shift)
    _ptrace(libc, _POKETEXT, pid, aligned, word)


# waitpid status helpers
def _WIFSTOPPED(s): return (s & 0xFF) == 0x7F
def _WSTOPSIG(s): return (s >> 8) & 0xFF
def _WIFEXITED(s): return (s & 0x7F) == 0
def _WEXITSTATUS(s): return (s >> 8) & 0xFF
def _WIFSIGNALED(s): return not _WIFSTOPPED(s) and not _WIFEXITED(s)
def _event(s): return (s >> 16) & 0xFF


def run_with_breakpoints(argv, breakpoints, *, env=None, cwd=None,
                         timeout: float = 30, max_hits: int = 1) -> dict:
    """Launch `argv` under ptrace, break at each address, and dump registers.

    breakpoints: list of {"addr": int, "dumps": [[reg, length], ...]}. On each
    hit the named registers are recorded, and for every (reg, length) dump the
    `length` bytes at the address in that register are read.

    Returns {"ran", "hits", "exit_code", "timed_out", "error"}. Each hit is
    {"addr", "tid", "registers": {name: int}, "dumps": {reg: hex}}. Never raises
    for a normal target that exits before a breakpoint (hits == []); raises
    PtraceUnsupported off x86-64 Linux.
    """
    if not _is_x86_64():
        raise PtraceUnsupported("ptrace breakpointing is x86-64 Linux only")
    if os.name != "posix":
        raise PtraceUnsupported("ptrace breakpointing requires Linux")

    result = {"ran": False, "hits": [], "exit_code": None,
              "timed_out": False, "error": None}
    bp_by_addr = {int(b["addr"]): b.get("dumps") or [] for b in breakpoints}

    child = os.fork()
    if child == 0:                                   # ---- child ----
        try:
            libc = _libc()
            libc.ptrace(_TRACEME, 0, None, None)
            if cwd:
                os.chdir(cwd)
            if env is None:
                os.execvp(argv[0], list(argv))
            else:
                os.execvpe(argv[0], list(argv), env)
        except Exception:
            os._exit(127)
        os._exit(127)

    # ---- parent (tracer) ----
    libc = _libc()
    originals: dict[int, int] = {}
    status = ctypes.c_int(0)

    def waitpid(pid=-1):
        r = libc.waitpid(pid, ctypes.byref(status), _WALL)
        return r, status.value

    timed_out = threading.Event()

    def watchdog():
        timed_out.set()
        try:
            os.kill(child, signal.SIGKILL)
        except OSError:
            pass
    timer = threading.Timer(timeout, watchdog)
    timer.daemon = True
    timer.start()

    try:
        # initial exec-stop of the main child
        pid, st = waitpid(child)
        if pid < 0:
            result["error"] = "initial waitpid failed"
            return result
        result["ran"] = True
        try:
            _ptrace(libc, _SETOPTIONS, child, 0, _OPTIONS)
        except OSError as exc:
            logger.debug("SETOPTIONS failed: %s", exc)
        # arm breakpoints (best-effort; a not-yet-mapped addr is skipped)
        for addr in list(bp_by_addr):
            try:
                _set_byte_cc(libc, child, addr, originals)
            except OSError as exc:
                logger.debug("could not arm bp @ %#x: %s (not mapped yet?)",
                             addr, exc)
        _ptrace(libc, _CONT, child, 0, 0)

        hits = 0
        while hits < max_hits:
            pid, st = waitpid()
            if pid < 0:
                break
            if timed_out.is_set():
                result["timed_out"] = True
                break
            if _WIFEXITED(st):
                if pid == child:
                    result["exit_code"] = _WEXITSTATUS(st)
                    break
                continue                              # a thread exited
            if _WIFSIGNALED(st):
                if pid == child:
                    break
                continue
            if not _WIFSTOPPED(st):
                continue
            sig = _WSTOPSIG(st)
            # ptrace event (clone/fork/exec) — just continue the stopped tid
            if sig == signal.SIGTRAP and _event(st) != 0:
                _ptrace(libc, _CONT, pid, 0, 0)
                continue
            if sig == signal.SIGTRAP:
                regs = _getregs(libc, pid)
                bp_addr = regs.rip - 1
                if bp_addr in bp_by_addr:
                    hit = {"addr": bp_addr, "tid": pid,
                           "registers": {n: getattr(regs, n) for n in _PUBLIC_REGS},
                           "dumps": {}}
                    for reg, length in bp_by_addr[bp_addr]:
                        if reg in _PUBLIC_REGS:
                            hit["dumps"][reg] = _read_mem(
                                pid, getattr(regs, reg), int(length)).hex()
                    result["hits"].append(hit)
                    hits += 1
                    # step over our 0xCC and re-arm
                    _restore_byte(libc, pid, bp_addr, originals)
                    regs.rip = bp_addr
                    _setregs(libc, pid, regs)
                    if hits < max_hits:
                        _ptrace(libc, _SINGLESTEP, pid, 0, 0)
                        waitpid(pid)
                        try:
                            _set_byte_cc(libc, pid, bp_addr, originals)
                        except OSError:
                            pass
                        _ptrace(libc, _CONT, pid, 0, 0)
                    continue
                # a SIGTRAP that isn't ours — forward nothing, keep going
                _ptrace(libc, _CONT, pid, 0, 0)
                continue
            # some other signal — forward it so the tracee behaves normally
            _ptrace(libc, _CONT, pid, sig, 0)
    except OSError as exc:
        result["error"] = f"{exc}"
    finally:
        timer.cancel()
        try:
            os.kill(child, signal.SIGKILL)
        except OSError:
            pass
        try:
            while True:
                r, _ = waitpid()
                if r < 0:
                    break
        except OSError:
            pass
    return result
