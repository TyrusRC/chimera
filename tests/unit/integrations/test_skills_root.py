from chimera.integrations.skills_root import skills_root


def test_env_override_wins(tmp_path, monkeypatch):
    d = tmp_path / "skills"
    d.mkdir()
    monkeypatch.setenv("CHIMERA_SKILLS_DIR", str(d))
    assert skills_root() == d


def test_missing_env_and_missing_dirs_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("CHIMERA_SKILLS_DIR", str(tmp_path / "nope"))
    assert skills_root() is None
