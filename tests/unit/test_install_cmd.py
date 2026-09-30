import json

from click.testing import CliRunner

from chimera.cli import main


def test_dry_run_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    r = CliRunner().invoke(main, ["install", "--dry-run", "--host", "claude-code"])
    assert r.exit_code == 0
    assert not (tmp_path / ".mcp.json").exists()


def test_installs_claude_code(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    r = CliRunner().invoke(main, ["install", "--host", "claude-code", "--portable"])
    assert r.exit_code == 0
    data = json.loads((tmp_path / ".mcp.json").read_text())
    assert "chimera" in data["mcpServers"]


def test_malformed_config_fails_that_host_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    (tmp_path / ".mcp.json").write_text("{ this is not json")
    r = CliRunner().invoke(main, ["install", "--host", "claude-code", "--portable"])
    assert r.exit_code != 0
    assert list(tmp_path.glob(".mcp.json.chimera-bak-*"))


def test_aborts_when_uvx_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("shutil.which", lambda name: None)
    r = CliRunner().invoke(main, ["install", "--host", "claude-code", "--project", "--portable"])
    assert r.exit_code != 0
    assert "uv" in r.output.lower()
    assert not (tmp_path / ".mcp.json").exists()


def test_user_scope_writes_claude_json(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    r = CliRunner().invoke(main, ["install", "--host", "claude-code", "--user", "--portable"])
    assert r.exit_code == 0
    data = json.loads((home / ".claude.json").read_text())
    assert "chimera" in data["mcpServers"]
