"""Chimera configuration — tool paths, resource limits, analysis options."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ChimeraConfig:
    project_dir: Path = field(default_factory=lambda: Path.cwd() / "chimera_project")
    cache_dir: Path = field(default_factory=lambda: Path.cwd() / "chimera_cache")
    ghidra_home: Optional[str] = None
    ghidra_max_mem: str = "4g"
    # Ghidra runs serially per-lib and dominates wall time on modern apps
    # with many native libs. These caps let analysts trade depth for
    # speed: skip libs over `ghidra_max_lib_mb`, and stop after
    # `ghidra_max_libs` libs have been analyzed. r2 + YARA + OLLVM still
    # run on every lib regardless. Set `ghidra_skip=True` to drop the
    # phase entirely. The defaults are sized so a typical RN app
    # (~20 libs, mostly <10 MB each) finishes in under 5 minutes.
    ghidra_max_lib_mb: int = 20
    ghidra_max_libs: int = 8
    ghidra_skip: bool = False
    total_ram_mb: Optional[int] = None
    skip_dynamic: bool = False
    skip_fuzzing: bool = True
    adb_device: Optional[str] = None
    ios_udid: Optional[str] = None
    mapping_file: Optional[Path] = None
    db_url: str = field(
        default_factory=lambda: os.getenv(
            "CHIMERA_DB_URL",
            "postgresql://chimera:chimera@localhost:5432/chimera_projects",
        )
    )
    pattern_db_url: str = field(
        default_factory=lambda: os.getenv(
            "CHIMERA_PATTERN_DB_URL",
            "postgresql://chimera:chimera@localhost:5432/chimera_patterns",
        )
    )

    def __post_init__(self):
        self.project_dir = Path(self.project_dir)
        self.cache_dir = Path(self.cache_dir)
        for name, path in (("project_dir", self.project_dir), ("cache_dir", self.cache_dir)):
            if path.exists() and not path.is_dir():
                raise ValueError(f"{name} is not a directory: {path}")
            path.mkdir(parents=True, exist_ok=True)
