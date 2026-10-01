"""Tests for the ILSpy newer-than-known-.NET compatibility shim."""
from __future__ import annotations

from chimera.dotnet.ilspy_compat import (
    compat_assembly, needs_compat_patch, patch_target_framework,
)


def _tf_blob(version_token: str) -> bytes:
    # Mimic the TargetFrameworkAttribute custom-attribute string region.
    return b"\x00\x01PREFIX" + f".NETCoreApp,Version={version_token}".encode() + b"\x01\x00tail"


def test_patch_rewrites_net10_length_preserving():
    data = _tf_blob("v10.0")
    out = patch_target_framework(data)
    assert out is not None
    assert len(out) == len(data)                 # byte length preserved (blob prefix stays valid)
    assert b".NETCoreApp,Version=v8.0," in out    # clamped to a recognised version
    assert b"v10.0" not in out


def test_patch_handles_two_digit_majors():
    for tok in ("v9.0", "v11.0", "v12.0"):
        data = _tf_blob(tok)
        out = patch_target_framework(data)
        assert out is not None and len(out) == len(data)
        # the version value parses to v8.0 (padding commas land after it)
        idx = out.index(b"Version=v") + len(b"Version=")
        assert out[idx:idx + 4] == b"v8.0"


def test_patch_skips_known_runtime():
    assert patch_target_framework(_tf_blob("v8.0")) is None
    assert patch_target_framework(_tf_blob("v6.0")) is None


def test_patch_skips_non_coreapp():
    assert patch_target_framework(b"random bytes, no target framework here") is None


def test_needs_and_compat_assembly(tmp_path):
    net10 = tmp_path / "net10.dll"
    net10.write_bytes(_tf_blob("v10.0"))
    net8 = tmp_path / "net8.dll"
    net8.write_bytes(_tf_blob("v8.0"))

    assert needs_compat_patch(net10) is True
    assert needs_compat_patch(net8) is False

    # net10: a temp, patched copy is yielded (different path) then cleaned up.
    with compat_assembly(net10) as p:
        assert p != str(net10)
        patched_path = p
        assert b"v8.0," in open(p, "rb").read()
    import os
    assert not os.path.exists(patched_path)  # temp removed on exit

    # net8: the original path is handed straight through (no copy).
    with compat_assembly(net8) as p:
        assert p == str(net8)
