"""Config validation behavior."""
from __future__ import annotations

import pytest

from chimera.core.config import ChimeraConfig


def test_config_rejects_file_as_project_dir(tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_bytes(b"")
    with pytest.raises(ValueError, match="not a directory"):
        ChimeraConfig(project_dir=f, cache_dir=tmp_path / "c")


def test_config_creates_missing_dirs(tmp_path):
    pdir = tmp_path / "new_project"
    cdir = tmp_path / "new_cache"
    ChimeraConfig(project_dir=pdir, cache_dir=cdir)
    assert pdir.is_dir() and cdir.is_dir()


def test_config_mapping_file_field_default_none(tmp_path):
    from chimera.core.config import ChimeraConfig
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    assert cfg.mapping_file is None


def test_config_mapping_file_field_accepts_path(tmp_path):
    from chimera.core.config import ChimeraConfig
    m = tmp_path / "mapping.txt"
    m.write_text("x -> a:\n")
    cfg = ChimeraConfig(
        project_dir=tmp_path / "p",
        cache_dir=tmp_path / "c",
        mapping_file=m,
    )
    assert str(cfg.mapping_file).endswith("mapping.txt")
