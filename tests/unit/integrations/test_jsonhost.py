import json
from pathlib import Path

from chimera.integrations.jsonhost import JsonHost

ENTRY = {"command": "/x/mcp-launch.sh", "args": ["mcp"]}


def _host(p: Path, root_key="mcpServers"):
    return JsonHost(name="test", path=p, root_key=root_key)


def test_adds_entry_to_empty(tmp_path):
    cfg = tmp_path / "c.json"
    _host(cfg).apply(ENTRY, dry_run=False)
    data = json.loads(cfg.read_text())
    assert data["mcpServers"]["chimera"] == ENTRY


def test_preserves_existing_server(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "y"}}}))
    _host(cfg).apply(ENTRY, dry_run=False)
    data = json.loads(cfg.read_text())
    assert data["mcpServers"]["other"] == {"command": "y"}
    assert data["mcpServers"]["chimera"] == ENTRY


def test_vscode_uses_servers_key(tmp_path):
    cfg = tmp_path / "c.json"
    _host(cfg, root_key="servers").apply(ENTRY, dry_run=False)
    assert json.loads(cfg.read_text())["servers"]["chimera"] == ENTRY


def test_idempotent_no_write_when_identical(tmp_path):
    cfg = tmp_path / "c.json"
    h = _host(cfg)
    h.apply(ENTRY, dry_run=False)
    mtime = cfg.stat().st_mtime_ns
    assert h.apply(ENTRY, dry_run=False) is None
    assert cfg.stat().st_mtime_ns == mtime


def test_dry_run_writes_nothing(tmp_path):
    cfg = tmp_path / "c.json"
    assert _host(cfg).apply(ENTRY, dry_run=True) is not None
    assert not cfg.exists()


def test_detect_defaults_to_parent(tmp_path):
    (tmp_path / "sub").mkdir()
    assert JsonHost("x", tmp_path / "sub" / "c.json").detect() is True


def test_detect_uses_markers_not_bare_parent(tmp_path):
    # A config rooted in an always-present dir (like cwd/.mcp.json) must not
    # auto-detect off the parent alone; a real host marker is required.
    cfg = tmp_path / ".mcp.json"
    h = JsonHost("claude-code", cfg, markers=[cfg, tmp_path / ".claude"])
    assert h.detect() is False
    (tmp_path / ".claude").mkdir()
    assert h.detect() is True
