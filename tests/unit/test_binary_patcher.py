"""Unit tests for BinaryPatcher — PE / ELF byte-level rewrites + checksum recompute."""
from __future__ import annotations

from pathlib import Path

import pytest

from chimera.patching.binary_patcher import (
    BinaryFormat,
    BinaryPatcher,
    PatchError,
    PatchPlan,
    _pe_checksum,
    detect_format,
)


FIXTURES = Path(__file__).resolve().parents[2] / "e2e" / "material" / "desktop"


def test_detect_format_recognises_each():
    assert detect_format(b"MZ\x90\x00") is BinaryFormat.PE
    assert detect_format(b"\x7fELF\x02\x01\x01\x00") is BinaryFormat.ELF
    assert detect_format(b"\xcf\xfa\xed\xfe") is BinaryFormat.MACHO
    assert detect_format(b"\xfe\xed\xfa\xcf") is BinaryFormat.MACHO
    assert detect_format(b"garbage") is BinaryFormat.UNKNOWN


def test_patch_plan_requires_one_address():
    with pytest.raises(ValueError):
        PatchPlan(bytes_=b"\x90")


# ------------------------------ PE round-trip ------------------------------


@pytest.mark.skipif(not (FIXTURES / "hello.exe").exists(), reason="hello.exe fixture missing")
def test_pe_open_detect_format():
    p = BinaryPatcher.open(FIXTURES / "hello.exe")
    assert p.fmt is BinaryFormat.PE


@pytest.mark.skipif(not (FIXTURES / "hello.exe").exists(), reason="hello.exe fixture missing")
def test_pe_patch_at_offset_round_trip(tmp_path):
    src = FIXTURES / "hello.exe"
    p = BinaryPatcher.open(src)
    # Pick a stable offset inside the PE header padding — every PE has
    # at least 0x200 bytes of headers, and bytes after the DOS stub but
    # before the section table are unused on most builds. Writing 0x90
    # here is harmless.
    target_offset = 0x150
    original = bytes(p.buffer[target_offset:target_offset + 4])
    result = p.patch_at_offset(target_offset, b"\x90\x90\x90\x90", description="nop")
    assert result.before == original
    assert result.after == b"\x90\x90\x90\x90"
    assert result.length == 4

    out = tmp_path / "patched.exe"
    p.save(out)
    written = out.read_bytes()
    assert written[target_offset:target_offset + 4] == b"\x90\x90\x90\x90"
    # The unmodified prefix must survive verbatim.
    assert written[:target_offset] == src.read_bytes()[:target_offset]


@pytest.mark.skipif(not (FIXTURES / "hello.exe").exists(), reason="hello.exe fixture missing")
def test_pe_save_default_path(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes((FIXTURES / "hello.exe").read_bytes())
    p = BinaryPatcher.open(src)
    p.patch_at_offset(0x150, b"\x90", description="single nop")
    out = p.save()
    assert out == tmp_path / "in.patched.exe"
    assert out.exists()


@pytest.mark.skipif(not (FIXTURES / "hello.exe").exists(), reason="hello.exe fixture missing")
def test_pe_dry_run_does_not_write(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes((FIXTURES / "hello.exe").read_bytes())
    p = BinaryPatcher.open(src)
    p.patch_at_offset(0x150, b"\xCC")
    out = p.save(tmp_path / "out.exe", dry_run=True)
    assert out == tmp_path / "out.exe"
    assert not out.exists()


# ------------------------------ ELF round-trip ------------------------------


@pytest.mark.skipif(not (FIXTURES / "hello").exists(), reason="hello ELF fixture missing")
def test_elf_open_detect_format():
    p = BinaryPatcher.open(FIXTURES / "hello")
    assert p.fmt is BinaryFormat.ELF


@pytest.mark.skipif(not (FIXTURES / "hello").exists(), reason="hello ELF fixture missing")
def test_elf_va_to_offset_resolves_text_segment(tmp_path):
    p = BinaryPatcher.open(FIXTURES / "hello")
    # Typical hello has a .text load at vaddr 0x1000-ish; if the fixture
    # is a stub we may not have anything there. Walk the ELF program
    # headers to find a real LOAD address to test against.
    from elftools.elf.elffile import ELFFile
    with open(FIXTURES / "hello", "rb") as fh:
        elf = ELFFile(fh)
        load_seg = next(
            (s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_filesz"] > 16),
            None,
        )
    if load_seg is None:
        pytest.skip("no PT_LOAD segment in fixture")
    vaddr = load_seg["p_vaddr"] + 0
    offset = p.va_to_offset(vaddr)
    assert offset == load_seg["p_offset"]


@pytest.mark.skipif(not (FIXTURES / "hello").exists(), reason="hello ELF fixture missing")
def test_elf_patch_at_offset_round_trip(tmp_path):
    src = FIXTURES / "hello"
    p = BinaryPatcher.open(src)
    # Pick a small offset that lives inside the file but well outside the
    # ELF header (which we don't want to corrupt). Use 0x100.
    target_offset = 0x100
    original = bytes(p.buffer[target_offset:target_offset + 2])
    p.patch_at_offset(target_offset, b"\x90\x90", description="elf nop")
    out = tmp_path / "patched"
    p.save(out)
    assert out.read_bytes()[target_offset:target_offset + 2] == b"\x90\x90"
    assert out.read_bytes()[target_offset:target_offset + 2] != original


# ------------------------------ guard rails ------------------------------


def test_open_rejects_unknown_format(tmp_path):
    f = tmp_path / "junk.bin"
    f.write_bytes(b"not a valid binary header at all" * 10)
    with pytest.raises(PatchError):
        BinaryPatcher.open(f)


def test_patch_out_of_bounds_raises(tmp_path):
    f = tmp_path / "x.elf"
    # Minimal ELF64 header so detect_format accepts it.
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
    p = BinaryPatcher.open(f)
    with pytest.raises(PatchError):
        p.patch_at_offset(0x10000, b"\x90")


def test_va_to_offset_rejects_unmapped(tmp_path):
    """Patching a VA that doesn't sit inside any LOAD segment must raise."""
    src = FIXTURES / "hello"
    if not src.exists():
        pytest.skip("no ELF fixture")
    p = BinaryPatcher.open(src)
    with pytest.raises(PatchError):
        p.va_to_offset(0xFFFFFFFF00000000)


def test_diff_summary_records_each_patch(tmp_path):
    f = tmp_path / "x.elf"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256)
    p = BinaryPatcher.open(f)
    p.patch_at_offset(0x40, b"\xab\xcd", description="first")
    p.patch_at_offset(0x60, b"\xef", description="second")
    summary = p.diff_summary()
    assert len(summary) == 2
    assert summary[0]["after"] == "abcd"
    assert summary[1]["description"] == "second"


# ------------------------------ PE checksum ------------------------------


def test_pe_checksum_is_deterministic():
    """The folded-sum algorithm must be referentially transparent on the same input."""
    buf = bytearray(b"\x00" * 0x1000)
    # Fill with non-zero so we exercise the fold, not just trivial zero math.
    for i in range(0x100, 0x900):
        buf[i] = i & 0xFF
    a = _pe_checksum(buf)
    b = _pe_checksum(buf)
    assert a == b
    assert a > 0


def test_pe_checksum_odd_length_handles_trailing_byte():
    buf = bytearray(b"\xff" * 1001)  # odd length
    assert _pe_checksum(buf) > 0
