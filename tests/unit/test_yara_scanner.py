"""Unit tests for the YARA scanner orchestration + bundled rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from chimera.bypass.yara_scanner import scan_native_lib


pytestmark = pytest.mark.asyncio


async def test_filename_packer_hint_works_without_yara(tmp_path):
    """Bangcle filename triggers commercial_packer even if yara is absent."""
    fake = tmp_path / "libsecexe.so"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 100)
    result = await scan_native_lib(fake, adapter=_DisabledAdapter())
    assert result["commercial_packer"] == "Bangcle"


async def test_no_filename_match_no_packer(tmp_path):
    fake = tmp_path / "libfoo.so"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 100)
    result = await scan_native_lib(fake, adapter=_DisabledAdapter())
    assert result["commercial_packer"] is None
    assert result["crypto_algorithms"] == []


async def test_aes_sbox_detected_via_bundled_rule(tmp_path):
    """If yara is installed, the bundled AES-SBOX rule fires on the constant."""
    yara = pytest.importorskip("yara")  # noqa: F841 — gate the test on the C ext
    fake = tmp_path / "libcrypto.so"
    aes_sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])
    fake.write_bytes(b"\x7fELF" + b"\x00" * 32 + aes_sbox + b"\x00" * 32)

    result = await scan_native_lib(fake)
    assert "AES" in result["crypto_algorithms"]


class _DisabledAdapter:
    """Mock that pretends yara-python is missing."""
    def is_available(self) -> bool:
        return False
