"""Recover AES keys by finding their expanded key schedule in a byte blob, a
file, or a live process's memory.

An AES implementation expands its key into a round-key schedule (176 bytes for
AES-128, 208 for AES-192, 240 for AES-256) whose words satisfy the KeyExpansion
recurrence. That structure is self-checking: a run of bytes either *is* a valid
schedule (astronomically unlikely by chance) or isn't. So a key that is computed
at runtime — derived, decrypted, or unpacked behind obfuscation, never a literal
in the file — can still be recovered from memory once the schedule is resident.
This is the classic `aeskeyfind` technique, aimed at RE: pair it with a memory
dump or a frozen process (see the dynamic-analysis skill) to lift a key the
static disassembly never spells out.

The original key is the first Nk words of the schedule. For the common
single-file AES (tiny-AES-c: `struct { uint8 RoundKey[]; uint8 Iv[16]; }`) the
16 bytes immediately after the schedule are reported as a candidate IV.

Pure Python, no dependencies. Read-only.
"""
from __future__ import annotations

import glob
import logging

logger = logging.getLogger(__name__)

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
         0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]

# nk (key words) -> (number of schedule words, schedule byte length, key bits)
_PARAMS = {4: (44, 176, 128), 6: (52, 208, 192), 8: (60, 240, 256)}


def _subword(w: bytes) -> bytes:
    return bytes(_SBOX[b] for b in w)


def expand_key(key: bytes) -> bytes:
    """Reference KeyExpansion — used by the tests and to reason about layout."""
    nk = len(key) // 4
    nw = _PARAMS[nk][0]
    w = [key[i * 4:i * 4 + 4] for i in range(nk)]
    for i in range(nk, nw):
        t = w[i - 1]
        if i % nk == 0:
            t = _subword(t[1:] + t[:1])
            t = bytes([t[0] ^ _RCON[i // nk - 1], t[1], t[2], t[3]])
        elif nk > 6 and i % nk == 4:
            t = _subword(t)
        w.append(bytes(a ^ b for a, b in zip(w[i - nk], t)))
    return b"".join(w)


def _valid_schedule(seg: bytes, nk: int) -> bool:
    nw = _PARAMS[nk][0]
    if len(seg) < nw * 4:
        return False
    w = [seg[i * 4:i * 4 + 4] for i in range(nw)]
    for i in range(nk, nw):
        t = w[i - 1]
        if i % nk == 0:
            t = _subword(t[1:] + t[:1])
            t = bytes([t[0] ^ _RCON[i // nk - 1], t[1], t[2], t[3]])
        elif nk > 6 and i % nk == 4:
            t = _subword(t)
        if bytes(a ^ b for a, b in zip(w[i - nk], t)) != w[i]:
            return False
    return True


def _prefilter(seg: bytes, nk: int) -> bool:
    """One cheap word check before the full validate (kills ~all noise)."""
    wm1 = seg[(nk - 1) * 4:nk * 4]
    t = _subword(wm1[1:] + wm1[:1])
    t = bytes([t[0] ^ _RCON[0], t[1], t[2], t[3]])
    return bytes(a ^ b for a, b in zip(seg[0:4], t)) == seg[nk * 4:nk * 4 + 4]


def find_key_schedules(data: bytes, *, bits=(256, 192, 128),
                       base: int = 0) -> list[dict]:
    """Scan `data` for valid AES key schedules; return one dict per key found.

    `bits` limits which key sizes to look for (default all three, largest first
    so a 256-bit schedule isn't misreported as a 128-bit prefix). `base` is added
    to each offset (pass a region's start VA when scanning process memory). Each
    result: {offset, address, bits, rounds, key (hex), iv_candidate (hex, the 16
    bytes after the schedule — tiny-AES-c layout)}.
    """
    nks = [nk for nk in (8, 6, 4) if _PARAMS[nk][2] in bits]
    out: list[dict] = []
    seen: set[tuple[int, str]] = set()
    n = len(data)
    for off in range(0, n, 4):                      # schedules are word-aligned
        if data[off:off + 8] == b"\x00" * 8:
            continue
        for nk in nks:
            slen = _PARAMS[nk][1]
            if off + slen > n:                      # not enough bytes for a schedule
                continue
            seg = data[off:off + slen]
            if _prefilter(seg, nk) and _valid_schedule(seg, nk):
                key = data[off:off + nk * 4]
                sig = (off, key.hex())
                if sig in seen:
                    continue
                seen.add(sig)
                out.append({
                    "offset": off,
                    "address": base + off,
                    "bits": _PARAMS[nk][2],
                    "rounds": _PARAMS[nk][0] // 4 - 1,
                    "key": key.hex(),
                    "iv_candidate": data[off + slen:off + slen + 16].hex(),
                })
                break                                # longest match wins this offset
    return out


def find_in_file(path, **kw) -> list[dict]:
    """Recover AES keys from a file (a memory dump, a core, or any blob)."""
    with open(path, "rb") as fh:
        return find_key_schedules(fh.read(), **kw)


def find_in_pid(pid: int, *, max_region: int = 256 * 1024 * 1024,
                writable_only: bool = True) -> list[dict]:
    """Recover AES keys from a live process's readable memory via /proc.

    Scans mapped regions (writable-only by default — a runtime key schedule lives
    in the stack/heap/.bss, not in a read-only image). Best-effort: a region can
    race or be unreadable; those are skipped. Returns the merged, de-duplicated
    findings with absolute virtual addresses.
    """
    found: list[dict] = []
    seen: set[str] = set()
    try:
        maps = open(f"/proc/{pid}/maps").read().splitlines()
        mem = open(f"/proc/{pid}/mem", "rb", 0)
    except OSError as exc:
        logger.debug("find_in_pid(%d): %s", pid, exc)
        return found
    try:
        for line in maps:
            parts = line.split()
            if len(parts) < 2:
                continue
            perms = parts[1]
            if "r" not in perms or (writable_only and perms[:2] != "rw"):
                continue
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
            if hi - lo <= 0 or hi - lo > max_region:
                continue
            try:
                mem.seek(lo)
                buf = mem.read(hi - lo)
            except (OSError, ValueError, OverflowError):
                continue
            for hit in find_key_schedules(buf, base=lo):
                if hit["key"] not in seen:
                    seen.add(hit["key"])
                    found.append(hit)
    finally:
        mem.close()
    return found
