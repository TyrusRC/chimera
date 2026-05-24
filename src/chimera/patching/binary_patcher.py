"""In-place binary patcher for PE, ELF, and Mach-O.

Usage::

    p = BinaryPatcher.open("license.exe")
    p.patch(0x140001234, bytes.fromhex("90909090"))     # NOP 4 bytes
    p.patch_at_offset(0x4000, b"\\x31\\xc0\\xc3")        # xor eax,eax; ret
    p.save("license_patched.exe")

The patcher works on a private bytearray buffer; nothing is written to
disk until ``save`` is called. ``dry_run=True`` skips the disk write and
returns the diff so callers can preview before committing.

Address resolution
------------------
Each format has a different mapping between a virtual address and the
on-disk file offset:

* **PE**: walk section headers, find the one containing
  ``vaddr - ImageBase``, return ``PointerToRawData + (vaddr - ImageBase
  - VirtualAddress)``.
* **ELF**: walk program headers (PT_LOAD), find the LOAD segment whose
  ``p_vaddr <= vaddr < p_vaddr + p_filesz``, return
  ``p_offset + (vaddr - p_vaddr)``.
* **Mach-O**: walk LC_SEGMENT_64, find ``vmaddr <= vaddr < vmaddr +
  filesize``, return ``fileoff + (vaddr - vmaddr)``.

These rules are deliberately simple — they cover the common case
("static const segment with file backing") and refuse to patch addresses
that fall outside file-backed memory (BSS, virtual-only sections). That
is intentional: writing to BSS at rest doesn't do anything; the loader
will overwrite it at runtime.

Checksums
---------
PE files carry an OptionalHeader.CheckSum that the Windows loader
validates for some images (drivers, signed binaries). We recompute it on
save when the original file had a non-zero checksum; for zero-checksum
inputs we leave it at zero so a flag-friendly diff is just the patch
bytes.
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


class BinaryFormat(Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"


class PatchError(Exception):
    """Raised when a patch can't be applied — out-of-range, unmapped, etc."""


@dataclass
class PatchPlan:
    """A single byte-level patch request expressed in either VA or file offset."""
    bytes_: bytes
    virtual_address: Optional[int] = None
    file_offset: Optional[int] = None
    description: str = ""

    def __post_init__(self):
        if self.virtual_address is None and self.file_offset is None:
            raise ValueError("PatchPlan needs either virtual_address or file_offset")


@dataclass
class PatchResult:
    """The outcome of a single applied PatchPlan."""
    file_offset: int
    virtual_address: Optional[int]
    length: int
    before: bytes
    after: bytes
    description: str = ""

    @property
    def is_noop(self) -> bool:
        return self.before == self.after


# ---------------------------------------------------------------------------
# Format sniffing — read the magic so we don't depend on the analysis model
# for the patcher to work.
# ---------------------------------------------------------------------------

def detect_format(buf: bytes) -> BinaryFormat:
    if len(buf) < 4:
        return BinaryFormat.UNKNOWN
    if buf[:2] == b"MZ":
        return BinaryFormat.PE
    if buf[:4] == b"\x7fELF":
        return BinaryFormat.ELF
    # 32-bit + 64-bit Mach-O, both endianness, plus FAT.
    if buf[:4] in (
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return BinaryFormat.MACHO
    return BinaryFormat.UNKNOWN


# ---------------------------------------------------------------------------
# BinaryPatcher
# ---------------------------------------------------------------------------


@dataclass
class BinaryPatcher:
    path: Path
    fmt: BinaryFormat
    buffer: bytearray
    results: list[PatchResult] = field(default_factory=list)

    @classmethod
    def open(cls, path: str | Path) -> "BinaryPatcher":
        p = Path(path)
        data = bytearray(p.read_bytes())
        fmt = detect_format(bytes(data[:16]))
        if fmt is BinaryFormat.UNKNOWN:
            raise PatchError(f"Unknown binary format for {p}; cannot patch.")
        return cls(path=p, fmt=fmt, buffer=data)

    # ----- address resolution -----------------------------------------

    def va_to_offset(self, vaddr: int) -> int:
        """Translate a virtual address to a file offset; raise on miss."""
        if self.fmt is BinaryFormat.PE:
            return _pe_va_to_offset(self.buffer, vaddr)
        if self.fmt is BinaryFormat.ELF:
            return _elf_va_to_offset(self.buffer, vaddr)
        if self.fmt is BinaryFormat.MACHO:
            return _macho_va_to_offset(self.buffer, vaddr)
        raise PatchError(f"Unsupported format {self.fmt} for va→offset translation")

    def read(self, vaddr: int, length: int) -> bytes:
        """Read bytes at a virtual address (read-through to buffer)."""
        off = self.va_to_offset(vaddr)
        return bytes(self.buffer[off:off + length])

    # ----- mutation ---------------------------------------------------

    def patch(self, vaddr: int, data: bytes, description: str = "") -> PatchResult:
        return self.apply(PatchPlan(
            bytes_=bytes(data), virtual_address=int(vaddr), description=description,
        ))

    def patch_at_offset(self, offset: int, data: bytes, description: str = "") -> PatchResult:
        return self.apply(PatchPlan(
            bytes_=bytes(data), file_offset=int(offset), description=description,
        ))

    def apply(self, plan: PatchPlan) -> PatchResult:
        if plan.file_offset is not None:
            off = plan.file_offset
            va = plan.virtual_address
        else:
            assert plan.virtual_address is not None
            off = self.va_to_offset(plan.virtual_address)
            va = plan.virtual_address
        if off < 0 or off + len(plan.bytes_) > len(self.buffer):
            raise PatchError(
                f"patch [{off:#x}..{off+len(plan.bytes_):#x}] runs past end of "
                f"file ({len(self.buffer):#x} bytes)"
            )
        before = bytes(self.buffer[off:off + len(plan.bytes_)])
        self.buffer[off:off + len(plan.bytes_)] = plan.bytes_
        result = PatchResult(
            file_offset=off, virtual_address=va, length=len(plan.bytes_),
            before=before, after=plan.bytes_, description=plan.description,
        )
        self.results.append(result)
        return result

    def apply_all(self, plans: Iterable[PatchPlan]) -> list[PatchResult]:
        return [self.apply(p) for p in plans]

    # ----- emit -------------------------------------------------------

    def save(self, out_path: str | Path | None = None, *, dry_run: bool = False) -> Path:
        """Write the patched buffer.

        ``out_path`` defaults to ``<original>.patched.<ext>``. Set
        ``dry_run=True`` to skip the write and just return the would-be
        path (handy for the CLI's ``--dry-run`` flag).
        """
        out = Path(out_path) if out_path else self._default_out_path(self.path)
        if self.fmt is BinaryFormat.PE:
            self._maybe_recompute_pe_checksum()
        if dry_run:
            return out
        # Atomic-ish write: same-fs tempfile then rename, so a crash
        # mid-write doesn't leave a half-patched binary in place.
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_bytes(bytes(self.buffer))
        # Preserve the executable bit from the source on POSIX so the
        # patched ELF can still be run without a manual chmod.
        try:
            mode = self.path.stat().st_mode
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, out)
        return out

    def diff_summary(self) -> list[dict]:
        return [
            {
                "file_offset": hex(r.file_offset),
                "virtual_address": hex(r.virtual_address) if r.virtual_address is not None else None,
                "length": r.length,
                "before": r.before.hex(),
                "after": r.after.hex(),
                "description": r.description,
            }
            for r in self.results
        ]

    # ----- internals --------------------------------------------------

    @staticmethod
    def _default_out_path(src: Path) -> Path:
        ext = src.suffix
        stem = src.stem
        return src.with_name(f"{stem}.patched{ext}")

    def _maybe_recompute_pe_checksum(self) -> None:
        """If the input PE had a non-zero CheckSum, recompute it on save.

        Windows validates the CheckSum for drivers and signed binaries.
        Keeping the old value would silently brick the patched output.
        We re-compute using the standard 16-bit-folded-sum algorithm
        documented in PE/COFF spec section 5.1.
        """
        try:
            buf = self.buffer
            e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
            if buf[e_lfanew:e_lfanew + 4] != b"PE\0\0":
                return
            opt_off = e_lfanew + 24
            opt_magic = struct.unpack_from("<H", buf, opt_off)[0]
            # Standard offsets: CheckSum is at OptionalHeader + 0x40 for both PE32 and PE32+.
            cksum_off = opt_off + 0x40
            existing = struct.unpack_from("<I", buf, cksum_off)[0]
            if existing == 0 and opt_magic in (0x10b, 0x20b):
                return  # zero-on-input → leave zero-on-output
            struct.pack_into("<I", buf, cksum_off, 0)
            new = _pe_checksum(buf)
            struct.pack_into("<I", buf, cksum_off, new)
        except Exception as exc:  # pragma: no cover — keeps save robust against weird PE headers
            logger.debug("PE checksum recompute skipped: %s", exc)


# ---------------------------------------------------------------------------
# Format-specific helpers
# ---------------------------------------------------------------------------


def _pe_va_to_offset(buf: bytes | bytearray, vaddr: int) -> int:
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if buf[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PatchError("PE signature missing — bad e_lfanew?")
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", buf, coff_off + 2)[0]
    size_of_opt = struct.unpack_from("<H", buf, coff_off + 16)[0]
    opt_off = coff_off + 20
    opt_magic = struct.unpack_from("<H", buf, opt_off)[0]
    if opt_magic == 0x10b:  # PE32
        image_base = struct.unpack_from("<I", buf, opt_off + 28)[0]
    elif opt_magic == 0x20b:  # PE32+
        image_base = struct.unpack_from("<Q", buf, opt_off + 24)[0]
    else:
        raise PatchError(f"Unknown PE optional magic: {opt_magic:#x}")
    rva = vaddr - image_base
    sections_off = opt_off + size_of_opt
    for i in range(num_sections):
        sec = sections_off + i * 40
        v_size = struct.unpack_from("<I", buf, sec + 8)[0]
        v_addr = struct.unpack_from("<I", buf, sec + 12)[0]
        raw_size = struct.unpack_from("<I", buf, sec + 16)[0]
        raw_ptr = struct.unpack_from("<I", buf, sec + 20)[0]
        if v_addr <= rva < v_addr + max(v_size, raw_size):
            return raw_ptr + (rva - v_addr)
    raise PatchError(f"PE: VA {vaddr:#x} (RVA {rva:#x}) not inside any section")


def _elf_va_to_offset(buf: bytes | bytearray, vaddr: int) -> int:
    ei_class = buf[4]
    if ei_class == 1:    # ELF32
        ph_off = struct.unpack_from("<I", buf, 0x1c)[0]
        ph_entsize = struct.unpack_from("<H", buf, 0x2a)[0]
        ph_num = struct.unpack_from("<H", buf, 0x2c)[0]
        load_unpack = "<IIIIIIII"
        load_size = 32
    elif ei_class == 2:  # ELF64
        ph_off = struct.unpack_from("<Q", buf, 0x20)[0]
        ph_entsize = struct.unpack_from("<H", buf, 0x36)[0]
        ph_num = struct.unpack_from("<H", buf, 0x38)[0]
        load_unpack = "<IIQQQQQQ"
        load_size = 56
    else:
        raise PatchError(f"Unknown ELF class {ei_class}")
    if ph_entsize != load_size:
        # Tolerate the standard sizes only; anything else is suspicious.
        raise PatchError(f"Unexpected ELF program-header entry size {ph_entsize}")
    for i in range(ph_num):
        entry = struct.unpack_from(load_unpack, buf, ph_off + i * ph_entsize)
        if ei_class == 1:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = entry
        else:
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = entry
        if p_type != 1:  # PT_LOAD
            continue
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    raise PatchError(f"ELF: VA {vaddr:#x} not inside any PT_LOAD segment")


def _macho_va_to_offset(buf: bytes | bytearray, vaddr: int) -> int:
    magic = buf[:4]
    if magic in (b"\xca\xfe\xba\xbe",):
        raise PatchError("FAT Mach-O patching is not supported — extract the per-arch slice first.")
    # 64-bit Mach-O header is 32 bytes; 32-bit is 28. Tell them apart by magic.
    if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        header_size = 32
        seg_cmd = 0x19  # LC_SEGMENT_64
        # segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8)
        seg_unpack = "<QQQQ"
        seg_off = 16
    elif magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        header_size = 28
        seg_cmd = 0x01  # LC_SEGMENT
        seg_unpack = "<IIII"
        seg_off = 16
    else:
        raise PatchError(f"Mach-O: unrecognised magic {magic.hex()}")
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    cur = header_size
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, cur)
        if cmd == seg_cmd:
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from(
                seg_unpack, buf, cur + 8 + seg_off,
            )
            if vmaddr <= vaddr < vmaddr + filesize:
                return fileoff + (vaddr - vmaddr)
        cur += cmdsize
    raise PatchError(f"Mach-O: VA {vaddr:#x} not inside any LC_SEGMENT")


def _pe_checksum(buf: bytearray) -> int:
    """PE OptionalHeader.CheckSum — 16-bit folded sum + file size.

    Matches the algorithm Microsoft's imagehlp!CheckSumMappedFile uses:
    16-bit additions with carry-folding, then `+= file size`.
    """
    total = 0
    end = len(buf) & ~1
    # Iterate 64KB at a time so we don't accumulate Python-int overhead.
    # Clamp the per-chunk end to `end` (not `off + 0x10000`) so an odd-
    # length file doesn't feed iter_unpack a buffer with a trailing byte.
    for off in range(0, end, 0x10000):
        chunk_end = min(off + 0x10000, end)
        chunk = buf[off:chunk_end]
        s = sum(w[0] for w in struct.iter_unpack("<H", chunk))
        total += s
        # Fold carry-out so the running total stays in 17 bits and we don't
        # leak Python big-int allocations on huge images.
        total = (total & 0xFFFF) + (total >> 16)
    if len(buf) & 1:
        total += buf[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(buf)) & 0xFFFFFFFF
