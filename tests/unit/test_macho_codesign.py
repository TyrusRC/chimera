"""Tests for the Mach-O code-signature reader + fat-slice extractor."""
from __future__ import annotations

import hashlib
import struct

import pytest

from chimera.parsers import macho_codesign as mc


def _codedir(identifier: bytes) -> bytes:
    """A minimal CodeDirectory blob (sha256) with an identifier at absolute offsets."""
    ident_off = 44
    blob = bytearray(ident_off)                   # header area
    struct.pack_into(">I", blob, 8, 0x20400)      # version @8
    struct.pack_into(">I", blob, 20, ident_off)   # identOffset @20
    blob[37] = 2                                  # hashType = sha256 @37
    blob += identifier + b"\x00"
    struct.pack_into(">I", blob, 0, mc._CSMAGIC_CODEDIRECTORY)  # magic @0
    struct.pack_into(">I", blob, 4, len(blob))    # length @4
    return bytes(blob)


def _thin_macho_with_sig(identifier: bytes) -> bytes:
    """A thin MH_MAGIC_64 Mach-O whose only load command is LC_CODE_SIGNATURE."""
    cd = _codedir(identifier)
    # SuperBlob: magic,len,count ; one index (type=0, offset=16) ; then CD
    sb = struct.pack(">III", mc._CSMAGIC_EMBEDDED_SIGNATURE, 12 + 8 + len(cd), 1)
    sb += struct.pack(">II", 0, 20) + cd
    header = struct.pack("<IiiIIIII", mc._MH_MAGIC_64, 0x100000C, 0, 2, 1, 16, 0, 0)
    dataoff = len(header) + 16
    lc = struct.pack("<IIII", mc.LC_CODE_SIGNATURE, 16, dataoff, len(sb))
    return header + lc + sb


def test_read_thin_identifier_and_cdhash():
    data = _thin_macho_with_sig(b"true_honest_flag")
    info = mc._read_one(data, 0)
    assert info.identifier == "true_honest_flag"
    assert info.hash_type == "sha256"
    assert info.has_signature
    # cdhash = sha256 of the CodeDirectory blob
    cd = _codedir(b"true_honest_flag")
    assert info.cdhash == hashlib.sha256(cd).hexdigest()


def test_fat_slices_and_extract(tmp_path):
    thin = _thin_macho_with_sig(b"slice_zero")
    nfat = 1
    fat = struct.pack(">II", mc._FAT_MAGIC, nfat)
    off = 8 + 20 * nfat
    fat += struct.pack(">IIIII", 0x100000C, 0, off, len(thin), 12)
    fat += thin
    slices = mc.fat_slices(fat)
    assert len(slices) == 1 and slices[0].offset == off and slices[0].size == len(thin)
    p = str(tmp_path / "f.macho")
    open(p, "wb").write(fat)
    out = str(tmp_path / "s0.macho")
    n = mc.extract_slice(p, 0, out)
    assert n == len(thin) and open(out, "rb").read() == thin


def test_not_a_macho_raises():
    import pathlib
    p = "/tmp/_not_macho_xyz.bin"
    pathlib.Path(p).write_bytes(b"hello not a macho")
    with pytest.raises(mc.MachoCodeSignError):
        mc.read_code_signatures(p)
