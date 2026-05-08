"""Unit tests for the ILSpy adapter (mocked subprocess + disk-walking)."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chimera.adapters.ilspy import IlspyAdapter, _walk_output


def test_ilspy_supported_formats():
    a = IlspyAdapter()
    assert a.supported_formats() == ["dotnet_pe"]


def test_ilspy_unavailable_returns_empty():
    a = IlspyAdapter()
    a._ilspy_bin = None
    out = asyncio.run(a.analyze("/nonexistent/x.dll", {"output_dir": "/tmp"}))
    assert out["available"] is False
    assert out["types"] == []
    assert out["type_count"] == 0


def test_ilspy_returns_error_when_output_dir_missing():
    a = IlspyAdapter()
    a._ilspy_bin = "/usr/bin/ilspycmd"
    out = asyncio.run(a.analyze("/x.dll", {}))
    assert out["available"] is True
    assert "error" in out
    assert out["error"] == "output_dir not provided"


def test_walk_output_finds_cs_files(tmp_path):
    # Build a fake ILSpy output tree
    (tmp_path / "Foo").mkdir()
    (tmp_path / "Foo" / "Bar.cs").write_text("class Bar {}")
    (tmp_path / "Foo" / "Baz.cs").write_text("class Baz {}")
    (tmp_path / "Top.cs").write_text("class Top {}")

    out = _walk_output(tmp_path, "myasm")
    assert out["assembly"] == "myasm"
    assert out["type_count"] == 3
    namespaces = {t["namespace"] for t in out["types"]}
    assert "Foo" in namespaces
    assert "" in namespaces  # top-level type has no namespace
    names = {t["name"] for t in out["types"]}
    assert {"Bar", "Baz", "Top"} <= names


def test_walk_output_empty_dir_returns_zero(tmp_path):
    out = _walk_output(tmp_path, "myasm")
    assert out["type_count"] == 0
    assert out["types"] == []


def test_analyze_success_walks_output(tmp_path):
    a = IlspyAdapter()
    a._ilspy_bin = "/usr/bin/ilspycmd"

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "MyType.cs").write_text("class MyType {}")

    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"", b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze(
            str(tmp_path / "x.dll"),
            {"output_dir": str(out_dir)},
        ))

    assert out["available"] is True
    assert out["type_count"] == 1
    assert out["types"][0]["name"] == "MyType"


def test_analyze_returns_error_on_nonzero_exit(tmp_path):
    a = IlspyAdapter()
    a._ilspy_bin = "/usr/bin/ilspycmd"

    out_dir = tmp_path / "out"
    proc = MagicMock()
    proc.returncode = 1
    proc.communicate = AsyncMock(return_value=(b"", b"ilspycmd: parse error"))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        out = asyncio.run(a.analyze(
            str(tmp_path / "x.dll"),
            {"output_dir": str(out_dir)},
        ))

    assert out["available"] is True
    assert "error" in out
    assert out["types"] == []
