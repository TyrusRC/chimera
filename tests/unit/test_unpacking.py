"""Unpacking module — detection + UPX shell-out + manual-guidance lookups."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from chimera.unpacking import (
    UnpackError,
    detect_packer,
    guidance_for,
    run_unpacker,
    unpacker_for,
)
from chimera.unpacking.detect import (
    Detection,
    _entropy,
    _looks_like_elf,
    _looks_like_pe,
    _SECTION_NAME_HINTS,
)


FIXTURES = Path(__file__).resolve().parents[2] / "e2e" / "material" / "desktop"


# ------------------------------ format sniff -------------------------------


def test_looks_like_pe_recognises_mz_header(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    assert _looks_like_pe(p) is True


def test_looks_like_elf_recognises_magic(tmp_path):
    p = tmp_path / "x.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert _looks_like_elf(p) is True


def test_sniffers_reject_other_magics(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\xca\xfe\xba\xbe")
    assert _looks_like_pe(p) is False
    assert _looks_like_elf(p) is False


def test_section_name_hint_patterns_match_upx_aspack_vmp():
    """Sanity check the regex map — bare-essentials assertions."""
    upx = _SECTION_NAME_HINTS["UPX"]
    assert any(p.match("UPX0") for p in upx)
    assert any(p.match("UPX1") for p in upx)
    assert any(p.match("UPX!") for p in upx)
    assert not any(p.match(".text") for p in upx)

    vmp = _SECTION_NAME_HINTS["VMProtect"]
    assert any(p.match(".vmp0") for p in vmp)
    assert any(p.match(".vmp1") for p in vmp)
    assert not any(p.match(".rdata") for p in vmp)


# ------------------------------ entropy ------------------------------------


def test_entropy_zero_for_empty_or_uniform():
    assert _entropy(b"") == 0.0
    assert _entropy(b"A" * 1024) == 0.0


def test_entropy_high_for_random():
    # 8 KiB of byte-uniform random data should approach 8.0.
    data = os.urandom(8192)
    e = _entropy(data)
    assert 7.5 < e <= 8.0, e


# ------------------------------ detect_packer ------------------------------


def test_detect_packer_unknown_input_returns_no_signal(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not-a-binary" * 100)
    det = detect_packer(p)
    assert det.packer is None
    # No signals because YARA can't compile against junk and our heuristics
    # only fire for PE/ELF.
    assert det.high_entropy_sections == 0


@pytest.mark.skipif(not (FIXTURES / "hello.exe").exists(), reason="hello.exe missing")
def test_detect_packer_clean_pe_reports_no_packer():
    det = detect_packer(FIXTURES / "hello.exe")
    # The synthesized fixture isn't packed, so YARA should be silent and
    # entropy heuristics should not trigger (stub binary, low entropy).
    assert det.packer is None


@pytest.mark.skipif(not (FIXTURES / "hello").exists(), reason="hello ELF missing")
def test_detect_packer_clean_elf_reports_no_packer():
    det = detect_packer(FIXTURES / "hello")
    assert det.packer is None


# ------------------- structural "suspected packed" signals ------------------
#
# Real packers routinely evade both the YARA pack and the section-name table
# (a renamed UPX stub, a bespoke protector). The section *table* still gives
# them away: an executable section with no bytes on disk has to be filled by
# a runtime stub, and a virtual size far exceeding the raw size means the
# same. Both shapes were measured against the crackmes-RE corpus and fired
# only on genuinely packed samples, never on clean ones.

def _build_pe(sections, *, machine=0x8664):
    """Synthesize a minimal pefile-parseable PE with the given sections.

    `sections` is a list of (name, virtual_size, raw_size, characteristics).
    Mirrors tests/fixtures/build_pe_fixture.py's layout.
    """
    import struct

    n = len(sections)
    BUF = 0x1000
    OPT_HDR_SIZE = 240
    buf = bytearray(BUF)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_off + 4,
                     machine, n, 0, 0, 0, OPT_HDR_SIZE, 0)
    opt = pe_off + 24
    struct.pack_into("<HBBIIII", buf, opt, 0x20b, 0, 0, 0x200, 0, 0, 0x1000)
    struct.pack_into("<IQ", buf, opt + 20, 0x1000, 0x140000000)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", buf, opt + 52, 0, 0x4000, 0x400, 0)
    struct.pack_into("<HH", buf, opt + 68, 3, 0)
    struct.pack_into("<I", buf, opt + 108, 16)
    sec = opt + OPT_HDR_SIZE
    va = 0x1000
    raw_off = 0x400
    for i, (name, vsize, raw_size, chars) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", buf, sec + i * 40,
                         name.encode().ljust(8, b"\x00"), vsize, va,
                         raw_size, raw_off if raw_size else 0,
                         0, 0, 0, 0, chars)
        va += 0x1000
        raw_off += raw_size
    return bytes(buf)


EXEC_SEC = 0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ
DATA_SEC = 0x40000040  # CNT_INITIALIZED_DATA | MEM_READ


def test_detect_flags_executable_section_with_no_raw_bytes(tmp_path):
    """An executable section with 0 bytes on disk must be filled at runtime."""
    p = tmp_path / "packed.exe"
    p.write_bytes(_build_pe([
        ("CODE", 0x15000, 0, EXEC_SEC),   # allocated but empty on disk
        (".rsrc", 0x200, 0x200, DATA_SEC),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is True
    assert any("zero_raw_exec_section" in s for s in det.signals)


def test_detect_flags_virtual_size_far_exceeding_raw(tmp_path):
    p = tmp_path / "packed2.exe"
    p.write_bytes(_build_pe([
        (".text", 0x8000, 0x200, EXEC_SEC),  # 64x larger in memory
        (".data", 0x200, 0x200, DATA_SEC),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is True
    assert any("virtual_size_exceeds_raw" in s for s in det.signals)


def test_data_section_bss_tail_is_not_flagged(tmp_path):
    """A data section far bigger in memory than on disk is just BSS.

    Applying the virtual-size rule to every section scored 0.56 precision
    on a labeled corpus; every false positive was .data/.idata/.reloc.
    """
    p = tmp_path / "bss.exe"
    p.write_bytes(_build_pe([
        (".text", 0x200, 0x200, EXEC_SEC),
        (".data", 0x8000, 0x200, DATA_SEC),  # uninitialized tail
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is False


def test_duplicate_section_names_alone_do_not_flag(tmp_path):
    """Measured on a labeled corpus: 0 true positives against 2 false ones.

    Real linkers emit repeated `.idata`/custom sections, so this shape was
    dropped rather than kept as a signal.
    """
    p = tmp_path / "dup.exe"
    p.write_bytes(_build_pe([
        ("DOSX", 0x200, 0x200, EXEC_SEC),
        ("DOSX", 0x200, 0x200, DATA_SEC),
        ("DOSX", 0x200, 0x200, DATA_SEC),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is False


def test_clean_pe_is_not_flagged_as_suspected_packed(tmp_path):
    """The signals must stay quiet on an ordinary layout — no false positives."""
    p = tmp_path / "clean.exe"
    p.write_bytes(_build_pe([
        (".text", 0x200, 0x200, EXEC_SEC),
        (".rdata", 0x200, 0x200, DATA_SEC),
        (".data", 0x200, 0x200, DATA_SEC),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is False
    assert det.packer is None


def test_named_packer_does_not_also_report_suspected(tmp_path):
    """`suspected_packed` is for *unattributed* evidence only."""
    p = tmp_path / "upx.exe"
    p.write_bytes(_build_pe([
        ("UPX0", 0x15000, 0, EXEC_SEC),
        ("UPX1", 0x200, 0x200, EXEC_SEC),
    ]))
    det = detect_packer(p)
    assert det.packer == "UPX"
    assert det.suspected_packed is False


# ------------------------------ unpacker_for -------------------------------


def test_unpacker_for_upx_returns_an_unpacker():
    u = unpacker_for("UPX")
    assert u is not None
    assert u.name == "upx"


def test_unpacker_for_unknown_returns_none():
    assert unpacker_for("Cryptor4000") is None
    assert unpacker_for("") is None


def test_guidance_for_known_protectors_returns_text():
    for name in ("themida", "vmprotect", "aspack", "pecompact", "mpress", "enigma"):
        msg = guidance_for(name)
        assert msg, name
        assert len(msg.splitlines()) >= 2


def test_guidance_for_unknown_returns_none():
    assert guidance_for("not-real") is None


# ------------------------------ UPX shell-out ------------------------------


def _have_upx() -> bool:
    return shutil.which("upx") is not None


@pytest.mark.skipif(not (_have_upx() and (FIXTURES / "hello").exists()),
                    reason="needs upx + hello ELF fixture")
def test_upx_round_trip_pack_then_unpack(tmp_path):
    """Pack a real ELF with upx, then have chimera invoke `upx -d`."""
    src = tmp_path / "hello"
    shutil.copy2(FIXTURES / "hello", src)
    # First, pack it.
    proc = subprocess.run(["upx", "-q", "-f", str(src)],
                          capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode != 0:
        # Stub ELFs often refuse to pack — skip rather than fail.
        pytest.skip(f"upx refused to pack the fixture: {proc.stderr[:200]}")

    # Detection should now flag UPX (either via YARA or section names).
    det = detect_packer(src)
    assert (det.packer or "").lower() == "upx", det.signals

    out = tmp_path / "hello.unpacked"
    unpacker = unpacker_for("upx")
    assert unpacker is not None
    result = run_unpacker(unpacker, src, out)
    assert result.output == out
    assert out.exists()
    assert result.unpacked_size > 0
    # An unpack actually grew the file (compressed -> inflated).
    assert result.unpacked_size >= result.original_size


def test_upx_unpacker_raises_when_tool_missing(tmp_path, monkeypatch):
    """If `upx` isn't on PATH the unpacker must surface a clear error."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    src = tmp_path / "input"
    src.write_bytes(b"\x00" * 16)
    unpacker = unpacker_for("upx")
    assert unpacker is not None
    with pytest.raises(UnpackError, match="upx not found"):
        run_unpacker(unpacker, src, tmp_path / "out")


def test_executable_bss_is_not_flagged(tmp_path):
    """Executable-but-uninitialized is a .bss-like region, not a packed stub.

    Measured against the labeled corpus this shape was the only source of
    false positives for the zero-raw signal.
    """
    CNT_UNINIT = 0x00000080
    p = tmp_path / "execbss.exe"
    p.write_bytes(_build_pe([
        (".text", 0x200, 0x200, EXEC_SEC),
        # executable + uninitialized-data + read, no raw bytes, no CNT_CODE
        ("CrackMe", 0x64, 0, 0x40000000 | 0x20000000 | CNT_UNINIT),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is False


def test_zero_raw_code_section_without_execute_bit_is_flagged(tmp_path):
    """Packers do emit zero-raw CNT_CODE sections that lack MEM_EXECUTE."""
    CNT_CODE = 0x00000020
    p = tmp_path / "packed3.exe"
    p.write_bytes(_build_pe([
        # read|write|code, zero raw — seen verbatim on a packed corpus sample
        ("sect_0", 0x10000, 0, 0xC0000000 | CNT_CODE),
        (".rsrc", 0x200, 0x200, DATA_SEC),
    ]))
    det = detect_packer(p)
    assert det.suspected_packed is True
    assert any("zero_raw_exec_section" in s for s in det.signals)


def test_tiny_high_entropy_section_is_not_counted(tmp_path):
    """Shannon entropy is bounded by log2(n) — small samples reach 8.0 free.

    A 256-byte executable section holding a jump/thunk table of distinct
    bytes scores a perfect 8.0 while being entirely ordinary code, so the
    estimate is only trustworthy over a large enough sample.
    """
    import struct
    body = bytes(range(256))          # 256 distinct bytes -> entropy 8.0
    p = tmp_path / "tiny.exe"
    raw = bytearray(_build_pe([
        (".text", len(body), len(body), EXEC_SEC),
    ]))
    raw[0x400:0x400 + len(body)] = body
    p.write_bytes(bytes(raw))
    det = detect_packer(p)
    assert det.high_entropy_sections == 0
