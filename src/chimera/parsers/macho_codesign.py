"""Read a Mach-O's code signature (CodeDirectory identifier + CDHash) and list/
extract its universal (fat) slices.

The code-signing **identifier** is an analyst signal: a challenge author can
label which fat slice is the real one through it (FLARE-On 13 ch3: the Crystal
arch slice signs as `true_honest_flag`, the decoy as `totally_fake_flag`), and
for malware it is the ad-hoc bundle id. It lives in `LC_CODE_SIGNATURE` →
CodeDirectory, which chimera had no reader for. The CDHash (hash of the
CodeDirectory) is the identity the OS verifies.

Also exposes the fat-slice table and a slice extractor — a fat slice's bytes are
already a complete thin Mach-O, so extracting one is a byte-range copy. All
read-only (except `extract_slice`, which writes the requested slice out).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from chimera.parsers.macho_objc_structs import LC_CODE_SIGNATURE, LINKEDIT_DATA_COMMAND

_MH_MAGIC_64 = 0xFEEDFACF          # thin 64-bit, little-endian on disk
_MH_MAGIC_32 = 0xFEEDFACE
_FAT_MAGIC = 0xCAFEBABE            # universal, big-endian
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_HASH_NAMES = {0: "none", 1: "sha1", 2: "sha256", 3: "sha384", 4: "sha256trunc"}


class MachoCodeSignError(Exception):
    pass


@dataclass
class Slice:
    cputype: int
    cpusubtype: int
    offset: int
    size: int


@dataclass
class CodeSignInfo:
    arch_offset: int               # file offset of the thin Mach-O this applies to
    identifier: str | None = None
    cdhash: str | None = None      # hex SHA of the CodeDirectory blob
    hash_type: str | None = None
    has_signature: bool = False

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def fat_slices(data: bytes) -> list[Slice]:
    """Parse a universal (fat) header → its arch slices; [] if not fat."""
    if len(data) < 8 or struct.unpack_from(">I", data, 0)[0] != _FAT_MAGIC:
        return []
    nfat = struct.unpack_from(">I", data, 4)[0]
    out = []
    for k in range(min(nfat, 64)):
        cput, csub, off, size, _align = struct.unpack_from(">IIIII", data, 8 + k * 20)
        out.append(Slice(cput, csub, off, size))
    return out


def _thin_offsets(data: bytes) -> list[int]:
    """File offsets of every thin Mach-O (the file itself, or each fat slice)."""
    slices = fat_slices(data)
    if slices:
        return [s.offset for s in slices]
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] in (_MH_MAGIC_64, _MH_MAGIC_32):
        return [0]
    raise MachoCodeSignError("not a Mach-O (no thin or fat magic)")


def _parse_codedir(data: bytes, cd_off: int) -> tuple[str | None, str, str]:
    """(identifier, cdhash_hex, hash_type) for the CodeDirectory blob at cd_off."""
    magic, length = struct.unpack_from(">II", data, cd_off)
    if magic != _CSMAGIC_CODEDIRECTORY:
        raise MachoCodeSignError("not a CodeDirectory blob")
    ident_off, = struct.unpack_from(">I", data, cd_off + 20)
    hash_type = data[cd_off + 37] if length > 37 else 0
    identifier = None
    if ident_off:
        end = data.index(b"\0", cd_off + ident_off)
        identifier = data[cd_off + ident_off:end].decode("utf-8", "replace")
    algo = {1: "sha1", 2: "sha256", 3: "sha384"}.get(hash_type, "sha256")
    h = getattr(hashlib, algo if algo != "sha256trunc" else "sha256")()
    h.update(data[cd_off:cd_off + length])
    cdhash = h.hexdigest()
    return identifier, cdhash, _HASH_NAMES.get(hash_type, str(hash_type))


def _read_one(data: bytes, base: int) -> CodeSignInfo:
    """Read the code signature of the thin Mach-O starting at `base`."""
    info = CodeSignInfo(arch_offset=base)
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in (_MH_MAGIC_64, _MH_MAGIC_32):
        return info
    is64 = magic == _MH_MAGIC_64
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + (32 if is64 else 28)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_CODE_SIGNATURE:
            _c, _sz, dataoff, _datasize = LINKEDIT_DATA_COMMAND.unpack_from(data, off)
            sb_off = base + dataoff
            sb_magic, _len, count = struct.unpack_from(">III", data, sb_off)
            if sb_magic == _CSMAGIC_EMBEDDED_SIGNATURE:
                info.has_signature = True
                for k in range(count):
                    _t, boff = struct.unpack_from(">II", data, sb_off + 12 + k * 8)
                    if struct.unpack_from(">I", data, sb_off + boff)[0] == _CSMAGIC_CODEDIRECTORY:
                        info.identifier, info.cdhash, info.hash_type = _parse_codedir(data, sb_off + boff)
                        break
            break
        off += cmdsize
    return info


def read_code_signatures(path: str) -> list[CodeSignInfo]:
    """One CodeSignInfo per arch (thin → one; fat → one per slice)."""
    data = Path(path).read_bytes()
    return [_read_one(data, base) for base in _thin_offsets(data)]


def extract_slice(path: str, index: int, out_path: str) -> int:
    """Write fat-slice #index (already a complete thin Mach-O) to out_path."""
    data = Path(path).read_bytes()
    slices = fat_slices(data)
    if not slices:
        raise MachoCodeSignError("not a fat Mach-O (no slices to extract)")
    if not 0 <= index < len(slices):
        raise MachoCodeSignError(f"slice index {index} out of range (0..{len(slices)-1})")
    s = slices[index]
    blob = data[s.offset:s.offset + s.size]
    Path(out_path).write_bytes(blob)
    return len(blob)
