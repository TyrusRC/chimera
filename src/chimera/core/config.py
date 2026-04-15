"""Chimera configuration — tool paths, resource limits, analysis options."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ChimeraConfig:
    project_dir: Path = field(default_factory=lambda: Path.cwd() / "chimera_project")
    cache_dir: Path = field(default_factory=lambda: Path.cwd() / "chimera_cache")
    ghidra_home: Optional[str] = None
    ghidra_max_mem: str = "4g"
    total_ram_mb: Optional[int] = None
    skip_dynamic: bool = False
    skip_fuzzing: bool = True
    adb_device: Optional[str] = None
    ios_udid: Optional[str] = None

    def __post_init__(self):
        self.project_dir = Path(self.project_dir)
        self.cache_dir = Path(self.cache_dir)
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
