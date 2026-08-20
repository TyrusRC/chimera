"""JVM (.jar) pipeline — jadx orchestration and model ingestion.

Driven with a stub jadx adapter so the pipeline logic is covered without
requiring jadx on PATH; a real end-to-end decompile is exercised by
tests/unit/test_jvm_format.py's routing plus manual verification.
"""
from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import get_resource_manager
from chimera.pipelines.jvm import analyze_jar


class _StubRegistry:
    def __init__(self, jadx):
        self._jadx = jadx

    def get(self, name):
        return self._jadx if name == "jadx" else None


class _StubJadx:
    """Writes a decompiled source tree the way jadx would."""

    def __init__(self, sources: dict[str, str] | None = None, available=True):
        self._sources = sources or {}
        self._available = available
        self.calls = 0

    def is_available(self):
        return self._available

    async def analyze(self, path, options):
        self.calls += 1
        out = Path(options["output_dir"]) / "sources"
        for rel, body in self._sources.items():
            f = out / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)
        return {
            "sources_dir": str(out),
            "decompiled_files": len(self._sources),
            "packages": ["com.example"],
        }


JAVA_CLASS = '''package com.example;

public class Main {
    public static void main(String[] args) {
        System.out.println("enter the license key please");
    }

    private boolean check(String serial) {
        return serial.equals("SUPERSECRETVALUE");
    }
}
'''


def _make_jar(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41")
    return path


def _run(jar, registry, tmp_path):
    config = ChimeraConfig(
        cache_dir=tmp_path / "cache",
        project_dir=tmp_path / "proj",
    )
    cache = AnalysisCache(config.cache_dir)
    return asyncio.run(analyze_jar(
        jar, config, registry, get_resource_manager(), cache,
    ))


def test_jar_pipeline_ingests_decompiled_classes(tmp_path):
    jar = _make_jar(tmp_path / "app.jar")
    jadx = _StubJadx({"com/example/Main.java": JAVA_CLASS})
    model = _run(jar, _StubRegistry(jadx), tmp_path)

    assert jadx.calls == 1
    assert len(model.functions) > 0
    names = {f.name for f in model.functions}
    assert any("Main" in n for n in names)


def test_jar_pipeline_reports_jvm_format_and_platform(tmp_path):
    jar = _make_jar(tmp_path / "app.jar")
    model = _run(jar, _StubRegistry(_StubJadx({"com/example/Main.java": JAVA_CLASS})),
                 tmp_path)
    assert model.binary.format.value == "jar"
    assert model.binary.platform.value == "jvm"


def test_jar_pipeline_recovers_string_literals(tmp_path):
    """String literals are the analyst's first lead on a keygen-me."""
    jar = _make_jar(tmp_path / "app.jar")
    model = _run(jar, _StubRegistry(_StubJadx({"com/example/Main.java": JAVA_CLASS})),
                 tmp_path)
    values = {s.value for s in model.get_strings()}
    assert "SUPERSECRETVALUE" in values


def test_jar_pipeline_degrades_without_jadx(tmp_path):
    """A .jar has no native fallback — must warn, not crash."""
    jar = _make_jar(tmp_path / "app.jar")
    model = _run(jar, _StubRegistry(_StubJadx(available=False)), tmp_path)
    assert len(model.functions) == 0
    assert model.binary.format.value == "jar"


def test_jar_pipeline_survives_a_jadx_failure(tmp_path):
    class _Exploding(_StubJadx):
        async def analyze(self, path, options):
            raise RuntimeError("jadx exploded")

    jar = _make_jar(tmp_path / "app.jar")
    model = _run(jar, _StubRegistry(_Exploding()), tmp_path)
    assert len(model.functions) == 0
