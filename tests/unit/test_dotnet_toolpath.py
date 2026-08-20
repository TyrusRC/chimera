"""Resolving .NET global tools that are not on PATH.

`dotnet tool install -g` puts executables in ~/.dotnet/tools, which is not
on the default PATH — its own install step only prints a hint to add it.
So a non-login shell (a launched MCP server, a cron job) cannot find
`ilspycmd` by name, and the .NET decompile silently degrades. chimera
looks in the standard global-tools directory too.
"""
from __future__ import annotations

import os
import stat

from chimera.dotnet.toolpath import find_dotnet_tool


def _make_exe(path):
    path.write_text("#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def test_finds_a_tool_on_path(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _make_exe(bindir / "ilspycmd")
    monkeypatch.setenv("PATH", str(bindir))
    assert find_dotnet_tool("ilspycmd") == str(bindir / "ilspycmd")


def test_falls_back_to_dotnet_tools_dir(tmp_path, monkeypatch):
    tools = tmp_path / ".dotnet" / "tools"
    tools.mkdir(parents=True)
    _make_exe(tools / "ilspycmd")
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert find_dotnet_tool("ilspycmd") == str(tools / "ilspycmd")


def test_respects_dotnet_tools_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom-tools"
    custom.mkdir()
    _make_exe(custom / "ilspycmd")
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("DOTNET_TOOLS_DIR", str(custom))
    assert find_dotnet_tool("ilspycmd") == str(custom / "ilspycmd")


def test_returns_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("DOTNET_TOOLS_DIR", raising=False)
    assert find_dotnet_tool("ilspycmd") is None


def test_path_takes_precedence_over_tools_dir(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"; bindir.mkdir()
    _make_exe(bindir / "ilspycmd")
    tools = tmp_path / ".dotnet" / "tools"; tools.mkdir(parents=True)
    _make_exe(tools / "ilspycmd")
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert find_dotnet_tool("ilspycmd") == str(bindir / "ilspycmd")
