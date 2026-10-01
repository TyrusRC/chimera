"""Run a self-contained function from a target binary at NATIVE speed, confined.

`emulate_function` (unicorn) is correct but ~10^4x too slow for a feasible brute
— e.g. a 2^32 volume-serial search over a tweaked-crypto routine (FLARE-On 13
"ToxicMiner": `flag = RC4(customSHA256d(serial‖const)[:16], ct)`, key keyed only
on the 4-byte disk serial). Re-implementing the tweaked hash by hand was wrong
twice; what won was running the ACTUAL bytes: map the PE's segments at their
preferred VAs and call the function via a Win64 ABI pointer (~180 ns/call → 2^32
in ~80 s on 10 cores).

This packages that: it derives the loadable segments from a PE/ELF, generates a
tiny C harness that `mmap`s them at their VAs (MAP_FIXED) and runs a caller-
supplied body (the target-specific loop/oracle — inherently bespoke), compiles
it with gcc, and runs the result **confined under bubblewrap** (network off,
throwaway home) — because it executes untrusted native code. The body calls the
target function through a `WIN64`/`SYSV` typedef and reads the binary path from
argv[1]. Absolute VAs work because segments load at their real addresses.

Safety: the untrusted target code runs inside the bwrap sandbox, never in the
chimera process. Without bwrap this refuses to run (pass `confine=False` only to
accept the risk of running unconfined).
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

PAGE = 0x1000


@dataclass
class Segment:
    va: int          # virtual address the bytes load at
    file_off: int    # offset of the bytes in the file
    size: int        # number of bytes to copy from the file


def _align_down(x: int) -> int:
    return x & ~(PAGE - 1)


def pe_segments(data: bytes) -> tuple[int, int, list[Segment]]:
    """(image_base, map_span, segments) for a PE (PE32 or PE32+)."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE\\0\\0)")
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:                       # PE32+
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B:                     # PE32
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    else:
        raise ValueError(f"unknown optional-header magic {magic:#x}")
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    segs = [Segment(image_base, 0, size_of_headers)]     # the headers page(s)
    sh = opt + opt_size
    for i in range(nsec):
        base = sh + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        if rawsize and rawptr:
            segs.append(Segment(image_base + vaddr, rawptr, min(rawsize, len(data) - rawptr)))
    return image_base, size_of_image, segs


def elf_segments(data: bytes) -> tuple[int, int, list[Segment]]:
    """(load_base, map_span, segments) for an ELF (PT_LOAD program headers).

    Absolute-VA (ET_EXEC) binaries load where their p_vaddr says; a PIE/ET_DYN
    (load bias 0) can't be pinned this way and is rejected.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    is64 = data[4] == 2
    if not is64:
        raise ValueError("only 64-bit ELF supported")
    e_type = struct.unpack_from("<H", data, 16)[0]
    if e_type not in (2, 3):
        raise ValueError(f"unexpected ELF e_type {e_type}")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs: list[Segment] = []
    lo, hi = None, 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph)[0]
        if p_type != 1:                      # PT_LOAD
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, ph + 8)
        p_filesz, p_memsz = struct.unpack_from("<QQ", data, ph + 32)
        segs.append(Segment(p_vaddr, p_offset, p_filesz))
        lo = p_vaddr if lo is None else min(lo, p_vaddr)
        hi = max(hi, p_vaddr + p_memsz)
    if not segs:
        raise ValueError("no PT_LOAD segments")
    if e_type == 3 and (lo or 0) == 0:
        raise ValueError("PIE/ET_DYN (load bias 0) not supported — needs absolute VAs")
    base = _align_down(lo)
    return base, hi - base, segs


def image_segments(path: str) -> tuple[int, int, list[Segment]]:
    """Dispatch on magic: PE (MZ) or ELF."""
    data = Path(path).read_bytes()
    if data[:2] == b"MZ":
        return pe_segments(data)
    if data[:4] == b"\x7fELF":
        return elf_segments(data)
    raise ValueError("unrecognised binary (not PE or ELF)")


_TEMPLATE = r"""#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#define WIN64 __attribute__((ms_abi))
#define SYSV  __attribute__((sysv_abi))
static const uint64_t CHIMERA_BASE = %(base)#xULL;
static uint8_t *IMG;
static void chimera_load(const char *path){
    int fd=open(path,O_RDONLY); if(fd<0){perror("open");_exit(3);}
    off_t fsz=lseek(fd,0,SEEK_END); lseek(fd,0,SEEK_SET);
    uint8_t *fb=(uint8_t*)malloc(fsz); if(!fb){_exit(3);}
    if(read(fd,fb,fsz)!=fsz){perror("read");_exit(3);} close(fd);
    void *base=mmap((void*)%(base)#xULL, %(span)#xULL,
                    PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if(base==MAP_FAILED){perror("mmap");_exit(3);}
    IMG=(uint8_t*)base;
%(copies)s
    free(fb);
}
%(preamble)s
int main(int argc, char **argv){
    if(argc<2){fprintf(stderr,"usage: %%s <binary>\n",argv[0]);return 2;}
    chimera_load(argv[1]);
%(body)s
    return 0;
}
"""


def generate_harness(image_base: int, span: int, segs: list[Segment],
                     body: str, preamble: str = "") -> str:
    """Emit the full C harness source."""
    lines = []
    for s in segs:
        off = s.va - image_base
        lines.append(f"    memcpy((uint8_t*)IMG + {off:#x}, fb + {s.file_off:#x}, {s.size:#x});")
    return _TEMPLATE % {
        "base": image_base, "span": span,
        "copies": "\n".join(lines), "preamble": preamble, "body": body,
    }


def gcc_available() -> bool:
    return shutil.which("gcc") is not None


def run_native_oracle(binary: str, body: str, *, preamble: str = "",
                      cflags: tuple[str, ...] = ("-O2",),
                      timeout: float = 300, confine: bool = True,
                      net: bool = False, env: dict | None = None) -> dict:
    """Map `binary`'s segments at their VAs and run `body` against them, confined.

    `body` is C inserted into main() after the image loads; `preamble` is C at
    file scope (typedefs, tables, helpers). The body reaches the target through
    absolute VAs, e.g. `typedef void (WIN64 *fn_t)(uint32_t,uint32_t,void*);
    ((fn_t)0x140134ca0)(...)`, and prints its findings to stdout.

    Returns {available, compiled, ran, returncode, stdout, stderr, error,
    image_base, span, nsegments, source}.
    """
    out = {"available": True, "compiled": False, "ran": False, "returncode": None,
           "stdout": "", "stderr": "", "error": None, "source": None}
    if not gcc_available():
        out["available"] = False
        out["error"] = "gcc not found on PATH"
        return out
    if not Path(binary).exists():
        out["error"] = f"binary not found: {binary}"
        return out
    try:
        base, span, segs = image_segments(binary)
    except ValueError as exc:
        out["error"] = f"segment parse failed: {exc}"
        return out
    out.update({"image_base": base, "span": span, "nsegments": len(segs)})
    src = generate_harness(base, span, segs, body, preamble)
    out["source"] = src

    tmp = tempfile.mkdtemp(prefix="chimera-native-")
    cfile = os.path.join(tmp, "harness.c")
    exe = os.path.join(tmp, "harness")
    Path(cfile).write_text(src)
    comp = subprocess.run([shutil.which("gcc"), *cflags, "-o", exe, cfile],
                          capture_output=True, text=True, timeout=120)
    if comp.returncode != 0:
        out["error"] = "gcc failed"
        out["stderr"] = comp.stderr
        return out
    out["compiled"] = True

    binary_abs = str(Path(binary).resolve())
    argv = [exe, binary_abs]
    if confine:
        from chimera.dynamic.sandbox import available as sbx_available
        from chimera.dynamic.sandbox import run_sandboxed
        if not sbx_available():
            out["error"] = ("bwrap not found — refusing to run untrusted native code "
                            "unconfined. `apt install bubblewrap`, or pass confine=False.")
            return out
        res = run_sandboxed(argv, ro_binds=(binary_abs, exe), timeout=timeout,
                            net=net, env=env)
        out["ran"] = res.get("ran", False)
        out["returncode"] = res.get("returncode")
        out["stdout"] = res.get("stdout", "")
        out["stderr"] = res.get("stderr", "")
        if res.get("error"):
            out["error"] = res["error"]
        if res.get("timed_out"):
            out["error"] = "timed out"
    else:
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                 env={**os.environ, **(env or {})})
            out["ran"] = True
            out["returncode"] = res.returncode
            out["stdout"] = res.stdout
            out["stderr"] = res.stderr
        except subprocess.TimeoutExpired:
            out["error"] = "timed out"
    return out
