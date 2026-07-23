"""Regression tests for the platform hardening pass.

Covers the logic-bearing security fixes: identifier sanitization (prompt-
injection boundary), decompression-bomb caps, analyze-path confinement, the
process-global ResourceManager, and the optional bearer-token auth.
"""

from __future__ import annotations

import asyncio
import stat
import zipfile
from pathlib import Path

import pytest

from chimera.ai.parsing import parse_rename_json, sanitize_symbol_name
from chimera.pipelines import safe_extract


# ----- H7: model-output identifier sanitization --------------------------

def test_sanitize_keeps_first_token_and_strips_metachars():
    # A crafted binary could steer the model into emitting shell/JS payloads.
    out = sanitize_symbol_name("main; rm -rf /")
    assert out is not None
    assert all(c.isalnum() or c == "_" for c in out)
    assert ";" not in out and " " not in out


def test_sanitize_digit_prefix_and_rejections():
    assert sanitize_symbol_name("123abc").startswith("_")
    assert sanitize_symbol_name("") is None
    assert sanitize_symbol_name("   ") is None
    assert sanitize_symbol_name("!!!") is None  # all non-ident → nothing usable
    assert sanitize_symbol_name("__stack_chk") == "__stack_chk"


def test_parse_rename_json_sanitizes_name():
    parsed = parse_rename_json('{"name": "evil\\nname drop", "confidence": 0.9}')
    assert parsed is not None
    assert parsed["name"] == "evil"  # first token only, newline/space dropped


# ----- H1: decompression-bomb caps ---------------------------------------

def _make_zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for n, data in files.items():
            z.writestr(n, data)


def test_zip_total_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_extract, "MAX_TOTAL_BYTES", 10)
    arc = tmp_path / "a.zip"
    _make_zip(arc, {"a.txt": b"x" * 50})
    with pytest.raises(safe_extract.ArchiveTooLargeError):
        safe_extract.safe_extract_zip(arc, tmp_path / "out")


def test_zip_member_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_extract, "MAX_MEMBERS", 1)
    arc = tmp_path / "m.zip"
    _make_zip(arc, {"a": b"1", "b": b"2"})
    with pytest.raises(safe_extract.ArchiveTooLargeError):
        safe_extract.safe_extract_zip(arc, tmp_path / "out")


def test_zip_slip_still_blocked(tmp_path):
    arc = tmp_path / "s.zip"
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("../evil.txt", b"x")
    with pytest.raises(safe_extract.UnsafeMemberError):
        safe_extract.safe_extract_zip(arc, tmp_path / "out")


def test_zip_symlink_member_blocked(tmp_path):
    arc = tmp_path / "l.zip"
    zi = zipfile.ZipInfo("link")
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr(zi, "/etc/passwd")
    with pytest.raises(safe_extract.UnsafeMemberError):
        safe_extract.safe_extract_zip(arc, tmp_path / "out")


def test_zip_happy_path(tmp_path):
    arc = tmp_path / "ok.zip"
    _make_zip(arc, {"a.txt": b"hello"})
    out = tmp_path / "out"
    safe_extract.safe_extract_zip(arc, out)
    assert (out / "a.txt").read_bytes() == b"hello"


# ----- C3: analyze-path confinement --------------------------------------

def test_analyze_path_rejects_outside_roots(tmp_path, monkeypatch):
    from fastapi import HTTPException
    from chimera.api.path_guard import assert_analyzable_path
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(tmp_path))
    monkeypatch.delenv("CHIMERA_ANALYZE_ROOTS", raising=False)
    with pytest.raises(HTTPException):
        assert_analyzable_path(Path("/etc/shadow"))


def test_analyze_path_allows_upload_dir(tmp_path, monkeypatch):
    from chimera.api.path_guard import assert_analyzable_path
    monkeypatch.setenv("CHIMERA_UPLOAD_DIR", str(tmp_path))
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    assert_analyzable_path(f)  # must not raise


# ----- H3: ResourceManager is a process singleton ------------------------

def test_resource_manager_is_singleton():
    from chimera.core.resource_manager import (
        get_resource_manager, reset_resource_manager,
    )
    reset_resource_manager()
    try:
        a = get_resource_manager(total_ram_mb=8192)
        b = get_resource_manager(total_ram_mb=65536)  # ignored — first wins
        assert a is b
        assert a.total_ram_mb == 8192
    finally:
        reset_resource_manager()


# ----- C1: optional bearer-token auth ------------------------------------

def test_auth_disabled_without_token(monkeypatch):
    from chimera.api.auth import require_auth
    monkeypatch.delenv("CHIMERA_API_TOKEN", raising=False)
    asyncio.run(require_auth(None))  # no token configured → allowed


def test_auth_enforced_with_token(monkeypatch):
    from fastapi import HTTPException
    from chimera.api.auth import require_auth
    monkeypatch.setenv("CHIMERA_API_TOKEN", "s3cret")
    with pytest.raises(HTTPException):
        asyncio.run(require_auth(None))
    with pytest.raises(HTTPException):
        asyncio.run(require_auth("Bearer wrong"))
    asyncio.run(require_auth("Bearer s3cret"))  # correct → allowed
