from chimera.integrations.dsh import DshHost

ENTRY = {"command": "/x/mcp-launch.sh", "args": ["mcp"], "env": {}}


def test_appends_block_when_absent(tmp_path):
    cfg = tmp_path / "cordis.patch.yml"
    h = DshHost(path=cfg, skills_dir=tmp_path / "skills")
    h.apply(ENTRY, dry_run=False)
    text = cfg.read_text()
    assert "id: mcp-chimera" in text
    assert "'@deepseek-ai/dsh-mcp-client'" in text
    assert "serverName: chimera" in text


def test_idempotent_when_row_present(tmp_path):
    cfg = tmp_path / "cordis.patch.yml"
    h = DshHost(path=cfg, skills_dir=tmp_path / "skills")
    h.apply(ENTRY, dry_run=False)
    first = cfg.read_text()
    assert h.apply(ENTRY, dry_run=False) is None
    assert cfg.read_text() == first
