"""Abstract base class for vulnerability detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from chimera.vuln.finding import Finding


class VulnRule(ABC):
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def title(self) -> str: ...

    @abstractmethod
    def severity_default(self) -> str: ...

    @abstractmethod
    def platforms(self) -> list[str]: ...

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[Finding]: ...


class ScanContext:
    """Context passed to each rule — provides access to analysis results."""

    def __init__(
        self,
        platform: str,
        manifest_path: Path | None = None,
        manifest_xml: str | None = None,
        jadx_sources_dir: Path | None = None,
        native_libs: list[Path] | None = None,
        strings: list[dict] | None = None,
        unpack_dir: Path | None = None,
    ):
        self.platform = platform
        self.manifest_path = manifest_path
        self.manifest_xml = manifest_xml
        self.jadx_sources_dir = jadx_sources_dir
        self.native_libs = native_libs or []
        self.strings = strings or []
        self.unpack_dir = unpack_dir
        self.ios_plist: dict = {}
        self.ios_entitlements: dict = {}

    def search_sources(self, pattern: str, glob: str = "**/*.java") -> list[tuple[Path, int, str]]:
        """Search decompiled source files for a regex pattern. Returns (file, line_num, line)."""
        if not self.jadx_sources_dir or not self.jadx_sources_dir.exists():
            return []
        import re
        regex = re.compile(pattern)
        results = []
        for source_file in self.jadx_sources_dir.glob(glob):
            try:
                for i, line in enumerate(source_file.read_text(errors="replace").splitlines(), 1):
                    if regex.search(line):
                        results.append((source_file, i, line.strip()))
            except OSError:
                continue
        return results
