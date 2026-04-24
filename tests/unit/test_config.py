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
