"""QEMU firmware-boot oracle — run a bootable image and capture its console.

The firmware analogue of run_under_wine / hdl_sim. `fw_extract` carves a UEFI
image statically; but some answers only appear at RUNTIME — a boot-stage
ransomware prints its note and part of a flag over the console, a bootkit only
reveals behaviour once it runs. This boots a firmware/disk image under QEMU
headless, captures the serial console, and can drive an interactive UEFI/DOS
shell by feeding scripted input lines over the serial line.

It is deliberately confined: no network (`-net none`), the disk mounted
copy-on-write (`snapshot=on`) so the image on disk is never modified, `-no-reboot`,
and a hard timeout. QEMU is external; without it this returns a clear
"not available" result rather than raising.
"""
from __future__ import annotations

import os
import pty
import re
import select
import shutil
import signal
import time
from pathlib import Path

_ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][B0]")


def qemu_available(qemu: str = "qemu-system-x86_64") -> bool:
    return _resolve(qemu) is not None


def _resolve(qemu: str) -> str | None:
    if os.sep in qemu:
        return qemu if Path(qemu).exists() else None
    return shutil.which(qemu)


def qemu_boot(*, bios: str | None = None, disk: str | None = None,
              input_lines: tuple[str, ...] = (), extra_args: tuple[str, ...] = (),
              boot_wait: float = 8.0, line_delay: float = 1.5,
              idle_timeout: float = 8.0, timeout: int = 90,
              qemu: str = "qemu-system-x86_64", memory_mb: int = 512,
              snapshot: bool = True, net: bool = False) -> dict:
    """Boot `bios`/`disk` under QEMU headless and capture the serial console.

    `input_lines` are typed into the guest console (each followed by CR) after
    `boot_wait` seconds, one every `line_delay` s — to drive a UEFI/EFI shell.
    Returns the captured (ANSI-stripped) console text. Confined: net off, disk
    copy-on-write, hard timeout.
    """
    exe = _resolve(qemu)
    if exe is None:
        return {"available": False,
                "error": "qemu-system-x86_64 not found — apt install qemu-system-x86"}
    if not bios and not disk:
        return {"available": True, "error": "need bios= and/or disk="}
    for label, p in (("bios", bios), ("disk", disk)):
        if p and not Path(p).exists():
            return {"available": True, "error": f"{label} not found: {p}"}

    cmd = [exe, "-nographic", "-no-reboot", "-m", str(memory_mb),
           "-machine", "accel=tcg"]
    if not net:
        cmd += ["-net", "none"]
    if bios:
        cmd += ["-bios", str(bios)]
    if disk:
        spec = f"format=raw,file={disk}" + (",snapshot=on" if snapshot else "")
        cmd += ["-drive", spec]
    cmd += list(extra_args)

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(exe, cmd)
        os._exit(127)

    out = bytearray()
    t0 = time.time()
    last_output = t0
    sent_idx = 0
    next_send = t0 + boot_wait
    lines = list(input_lines)
    try:
        while time.time() - t0 < timeout:
            r, _, _ = select.select([fd], [], [], 0.5)
            now = time.time()
            if fd in r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                last_output = now
            if sent_idx < len(lines) and now >= next_send:
                try:
                    os.write(fd, (lines[sent_idx] + "\r").encode())
                except OSError:
                    pass
                sent_idx += 1
                next_send = now + line_delay
            # stop early once input is done and the console has gone quiet
            if sent_idx >= len(lines) and now - last_output > idle_timeout:
                break
    finally:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            time.sleep(0.15)
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass

    text = _ANSI.sub(b"", bytes(out)).decode("latin-1", errors="replace")
    return {"available": True, "output": text, "bytes": len(out),
            "timed_out": time.time() - t0 >= timeout, "cmd": " ".join(cmd),
            "inputs_sent": sent_idx,
            "note": "headless QEMU serial capture"
                    + ("; drove console input" if lines else "")}
