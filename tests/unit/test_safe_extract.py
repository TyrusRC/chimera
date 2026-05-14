"""Tests for safe_extract — must reject zip-slip attempts."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from chimera.pipelines.safe_extract import safe_extract_zip, UnsafeMemberError


def _make_zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members:
            zf.writestr(name, content)
    return buf.getvalue()


def test_extracts_normal_archive(tmp_path):
    archive = tmp_path / "ok.zip"
    archive.write_bytes(_make_zip([("a.txt", b"hello"), ("sub/b.txt", b"world")]))
    out = tmp_path / "out"
    safe_extract_zip(archive, out)
    assert (out / "a.txt").read_bytes() == b"hello"
    assert (out / "sub" / "b.txt").read_bytes() == b"world"


def test_rejects_absolute_path_member(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(_make_zip([("/etc/passwd", b"haha")]))
    out = tmp_path / "out"
    with pytest.raises(UnsafeMemberError):
        safe_extract_zip(archive, out)


def test_rejects_parent_traversal_member(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(_make_zip([("../../escape.txt", b"haha")]))
    out = tmp_path / "out"
    with pytest.raises(UnsafeMemberError):
        safe_extract_zip(archive, out)
