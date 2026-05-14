"""engine.analyze on an unrecognized binary returns a structured error
(not a raw ValueError) and lists supported formats."""
from __future__ import annotations

import pytest

from chimera.core.config import ChimeraConfig
from chimera.core.engine import ChimeraEngine, UnsupportedFormatError


@pytest.mark.asyncio
async def test_engine_unknown_format_raises_unsupported_format_error(tmp_path):
    """Garbage bytes that match no magic produce UnsupportedFormatError."""
    p = tmp_path / "garbage.bin"
    p.write_bytes(b"\x00\xff\xab\xcd" * 16)
    engine = ChimeraEngine(ChimeraConfig())
    try:
        with pytest.raises(UnsupportedFormatError) as exc_info:
            await engine.analyze(p)
        msg = str(exc_info.value).lower()
        assert "supported" in msg
        # Each supported format family should be mentioned at least once.
        for token in ("apk", "ipa", "macho", "pe", "elf"):
            assert token in msg, f"missing {token!r} in error message: {msg}"
    finally:
        await engine.cleanup()


def test_unsupported_format_error_carries_detected_and_path():
    """The error attributes are introspectable for callers (status text, telemetry)."""
    err = UnsupportedFormatError("widget", "/tmp/x.widget")
    assert err.detected_format == "widget"
    assert err.path == "/tmp/x.widget"
    msg = str(err)
    assert "widget" in msg
    assert "/tmp/x.widget" in msg
