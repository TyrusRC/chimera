"""UEFI firmware carving: detection, module classification, graceful degrade.

The full carve of a real image is verified out-of-band (uefi_firmware is an
optional extra); these cover the dependency-free logic.
"""
from __future__ import annotations

from chimera.unpacking import uefi
from chimera.model.binary import BinaryFormat, _detect_format


def _fv_blob() -> bytes:
    # 0xFF padding with the _FVH signature at the volume-header offset 0x28.
    b = bytearray(b"\xff" * 0x100)
    b[0x28:0x2c] = b"_FVH"
    return bytes(b)


def test_is_uefi_firmware_signature_at_offset():
    assert uefi.is_uefi_firmware(_fv_blob()) is True


def test_is_uefi_firmware_signature_deeper_in_head():
    b = bytearray(b"\x00" * 0x2000)
    b[0x1000:0x1004] = b"_FVH"
    assert uefi.is_uefi_firmware(bytes(b)) is True


def test_is_uefi_firmware_absent():
    assert uefi.is_uefi_firmware(b"\x00" * 0x1000) is False


def test_detect_format_recognises_firmware(tmp_path):
    f = tmp_path / "bios.bin"
    f.write_bytes(_fv_blob())
    assert _detect_format(f) is BinaryFormat.UEFI_FIRMWARE


def test_module_kind():
    assert uefi._module_kind(b"MZ\x90\x00") == "PE"
    assert uefi._module_kind(b"VZ\x00\x00") == "TE"
    assert uefi._module_kind(b"\x00\x00") is None


def test_looks_like_name_filters_guids_and_versions():
    assert uefi._looks_like_name("Shell") is True
    assert uefi._looks_like_name("BdsDxe") is True
    assert uefi._looks_like_name("7c04a583-9e3e-4f1c-ad65-e05268d0b4d1") is False
    assert uefi._looks_like_name("1.0") is False
    assert uefi._looks_like_name("") is False
    assert uefi._looks_like_name(None) is False


def test_carve_degrades_without_lib(tmp_path, monkeypatch):
    f = tmp_path / "bios.bin"
    f.write_bytes(_fv_blob())
    monkeypatch.setattr(uefi, "uefi_available", lambda: False)
    r = uefi.carve_firmware(str(f))
    assert r["available"] is False and "uefi_firmware" in r["error"]


def test_carve_rejects_non_firmware(tmp_path):
    f = tmp_path / "notfw.bin"
    f.write_bytes(b"\x00" * 0x1000)
    if not uefi.uefi_available():
        return  # graceful-degrade path already covered above
    r = uefi.carve_firmware(str(f))
    assert r["available"] and r["is_firmware"] is False
