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

A breakpoint is given either as a fixed "addr", or as a byte "signature" + a
signed "delta": the signature is located in memory at runtime and the breakpoint
armed at found+delta. Signature+delta is ASLR-proof — resolve a module's
randomised base from a known code/data pattern (e.g. an AES S-box) without
knowing where the loader put it. An address (or signature) not resident at the
exec-stop is armed later by a poller that watches the traced tree's maps.

Ceilings, stated honestly:
- x86-64 Linux only.
- Deferred/signature arming is best-effort: it needs the target *alive* long
  enough for the poller to scan and arm before the target reaches the
  breakpoint. A microsecond-lived program can win the race; a validator waiting
  on input, or an app with network latency, gives ample time.
- **Wine-hosted PE**: the Wine loader reparents the actual PE process out of our
  descendant tree, so under `kernel.yama.ptrace_scope=1` we can neither trace it
  nor read its /proc/<pid>/mem — the no-sudo path reaches a native ELF child but
  not the Wine PE. Grabbing a key from a PE-under-Wine needs `ptrace_scope=0`
  (then attach/gdb works) or a core dump.
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
_GETEVENTMSG = 0x4201
# option bits
_O_EXITKILL = 0x00100000
_O_TRACECLONE = 0x00000008
_O_TRACEFORK = 0x00000002
_O_TRACEVFORK = 0x00000004
_O_TRACEEXEC = 0x00000010
_OPTIONS = _O_EXITKILL | _O_TRACECLONE | _O_TRACEFORK | _O_TRACEVFORK | _O_TRACEEXEC
_WALL = 0x40000000
_WNOHANG = 0x00000001

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


def _addr_mapped(pid: int, addr: int, *, executable: bool = True) -> bool:
    """True if `addr` falls in a mapped (executable) region of pid's memory."""
    try:
        with open(f"/proc/{pid}/maps") as fh:
            for line in fh:
                rng, perms = line.split()[0], line.split()[1]
                lo, hi = (int(x, 16) for x in rng.split("-"))
                if lo <= addr < hi:
                    return (not executable) or "x" in perms
    except OSError:
        pass
    return False


def _scan_sig(pid: int, sig: bytes, *, max_region: int = 64 * 1024 * 1024):
    """First address of `sig` in pid's readable memory, or None. Used to resolve
    an ASLR'd module base at runtime from a known code/data pattern."""
    try:
        maps = open(f"/proc/{pid}/maps").read().splitlines()
        mem = open(f"/proc/{pid}/mem", "rb", 0)
    except OSError:
        return None
    try:
        for line in maps:
            p = line.split()
            if len(p) < 2 or "r" not in p[1]:
                continue
            lo, hi = (int(x, 16) for x in p[0].split("-"))
            if hi - lo <= 0 or hi - lo > max_region:
                continue
            try:
                mem.seek(lo)
                buf = mem.read(hi - lo)
            except (OSError, ValueError, OverflowError):
                continue
            k = buf.find(sig)
            if k >= 0:
                return lo + k
    finally:
        mem.close()
    return None


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
                         timeout: float = 30, max_hits: int = 1,
                         defer: bool = True) -> dict:
    """Launch `argv` under ptrace, break at each address, and dump registers.

    breakpoints: list of {"addr": int, "dumps": [[reg, length], ...]}. On each
    hit the named registers are recorded, and for every (reg, length) dump the
    `length` bytes at the address in that register are read.

    `defer` (default True): an address not yet mapped at the exec-stop is armed
    later — a poller watches the traced process tree's memory maps and arms each
    breakpoint the moment its address appears (in any traced pid). This is what
    lets you break inside a Windows PE the Wine loader maps after launch, or a
    dlopen'd/JIT'd region. Set defer=False for the plain arm-at-launch behaviour.

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
    # A breakpoint is either at a fixed "addr", or at a byte "signature" found in
    # memory plus a signed "delta" — signature+delta is ASLR-proof (resolve the
    # module base at runtime from a known code/data pattern, e.g. an AES S-box).
    bp_by_addr = {int(b["addr"]): b.get("dumps") or []
                  for b in breakpoints if "addr" in b}
    sig_specs = [{"sig": bytes.fromhex(b["signature"]) if isinstance(b["signature"], str)
                  else bytes(b["signature"]),
                  "delta": int(b.get("delta", 0)), "dumps": b.get("dumps") or [],
                  "done": False}
                 for b in breakpoints if "signature" in b]

    child = os.fork()
    if child == 0:                                   # ---- child ----
        try:
            os.setpgid(0, 0)                         # own process group (safe killpg)
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

    def waitpid(pid=-1, block=True):
        flags = _WALL if block else (_WALL | _WNOHANG)
        r = libc.waitpid(pid, ctypes.byref(status), flags)
        return r, status.value

    timed_out = threading.Event()

    def watchdog():
        timed_out.set()
        for killer in (lambda: os.killpg(child, signal.SIGKILL),   # child is pgroup leader
                       lambda: os.kill(child, signal.SIGKILL)):
            try:
                killer()
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
        # arm what's already mapped now; the rest are deferred to the poller.
        pending: set[int] = set()
        pend_lock = threading.Lock()
        for addr in list(bp_by_addr):
            try:
                _set_byte_cc(libc, child, addr, originals)
            except OSError:
                pending.add(addr)
        traced = {child}                              # pids we're tracing
        want_arm: dict[int, set[int]] = {}            # pid -> addrs to arm on its next stop

        def poller():
            # Watch every traced pid: arm a pending fixed addr once it maps, and
            # resolve a signature bp by scanning memory, then stop that pid so
            # the main loop can POKETEXT the 0xCC in.
            while not timed_out.is_set():
                with pend_lock:
                    todo = set(pending)
                    specs = [s for s in sig_specs if not s["done"]]
                    pids = list(traced)
                if not todo and not specs:
                    return
                for a in todo:
                    for p in pids:
                        if _addr_mapped(p, a):
                            with pend_lock:
                                want_arm.setdefault(p, set()).add(a)
                            try:
                                os.kill(p, signal.SIGSTOP)
                            except OSError:
                                pass
                            break
                for s in specs:
                    for p in pids:
                        at = _scan_sig(p, s["sig"])
                        if at is not None:
                            addr = at + s["delta"]
                            with pend_lock:
                                bp_by_addr[addr] = s["dumps"]
                                want_arm.setdefault(p, set()).add(addr)
                                s["done"] = True
                            try:
                                os.kill(p, signal.SIGSTOP)
                            except OSError:
                                pass
                            break
                threading.Event().wait(0.02)

        if defer and (pending or sig_specs):
            pt = threading.Thread(target=poller, daemon=True)
            pt.start()
        _ptrace(libc, _CONT, child, 0, 0)

        hits = 0
        while hits < max_hits:
            if timed_out.is_set():
                result["timed_out"] = True
                break
            pid, st = waitpid(block=False)          # poll so the timeout can fire
            if pid == 0:                            # nothing ready yet
                threading.Event().wait(0.001)
                continue
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
            # ptrace event (clone/fork/exec) — track the new pid, then continue.
            if sig == signal.SIGTRAP and _event(st) != 0:
                if _event(st) in (1, 2, 3):           # FORK / VFORK / CLONE
                    try:
                        newpid = ctypes.c_ulong(0)
                        _ptrace(libc, _GETEVENTMSG, pid, 0,
                                ctypes.cast(ctypes.byref(newpid), ctypes.c_void_p).value)
                        with pend_lock:
                            traced.add(newpid.value)
                    except OSError:
                        pass
                _ptrace(libc, _CONT, pid, 0, 0)
                continue
            # a stop we (the poller) requested so we can arm a deferred bp here
            if sig == signal.SIGSTOP and pid in want_arm:
                with pend_lock:
                    addrs = want_arm.pop(pid, set())
                for a in addrs:
                    try:
                        _set_byte_cc(libc, pid, a, originals)
                        with pend_lock:
                            pending.discard(a)
                    except OSError:
                        pass
                _ptrace(libc, _CONT, pid, 0, 0)       # suppress the SIGSTOP
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
            # a new-child init stop or a stray SIGSTOP — resume without redelivery
            if sig == signal.SIGSTOP:
                _ptrace(libc, _CONT, pid, 0, 0)
                continue
            # some other signal — forward it so the tracee behaves normally
            _ptrace(libc, _CONT, pid, sig, 0)
    except OSError as exc:
        result["error"] = f"{exc}"
    finally:
        timer.cancel()
        for killer in (lambda: os.killpg(child, signal.SIGKILL),
                       lambda: os.kill(child, signal.SIGKILL)):
            try:
                killer()
            except OSError:
                pass
        try:
            for _ in range(10000):
                r, _ = waitpid(block=False)
                if r <= 0:
                    break
        except OSError:
            pass
    return result
