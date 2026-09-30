import tomllib

from chimera.integrations.codex import CodexHost

ENTRY = {"command": "/x/mcp-launch.sh", "args": ["mcp"], "env": {}}


def test_writes_valid_toml_table(tmp_path):
    cfg = tmp_path / "config.toml"
    CodexHost(path=cfg).apply(ENTRY, dry_run=False)
    data = tomllib.loads(cfg.read_text())
    assert data["mcp_servers"]["chimera"]["command"] == "/x/mcp-launch.sh"
    assert data["mcp_servers"]["chimera"]["args"] == ["mcp"]


def test_preserves_existing_table(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[mcp_servers.other]\ncommand = "y"\nargs = ["z"]\n')
    CodexHost(path=cfg).apply(ENTRY, dry_run=False)
    data = tomllib.loads(cfg.read_text())
    assert data["mcp_servers"]["other"]["command"] == "y"
    assert data["mcp_servers"]["chimera"]["command"] == "/x/mcp-launch.sh"


def test_idempotent(tmp_path):
    cfg = tmp_path / "config.toml"
    h = CodexHost(path=cfg)
    h.apply(ENTRY, dry_run=False)
    assert h.apply(ENTRY, dry_run=False) is None
