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
