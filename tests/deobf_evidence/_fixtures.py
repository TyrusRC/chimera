"""Fixture sample regeneration + sha256 verification.

Samples are NOT committed. build.sh regenerates into .cache/ on demand.
Missing build tools -> pytest.skip with the exact tool name.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


def _fixture_dir(variant: str) -> Path:
    d = FIXTURES_ROOT / variant
    if not d.exists():
        raise FileNotFoundError(f"Fixture dir missing: {d}")
    return d


def load_expected(variant: str) -> dict:
    with (_fixture_dir(variant) / "expected.json").open() as f:
        return json.load(f)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_sample(variant: str) -> Path:
    """Build or reuse the cached synthetic sample for a variant.

    Skips the calling test if a required build tool is missing.
    Raises AssertionError if the built sample sha256 does not match
    expected.json (drift in toolchain).
    """
    fixture = _fixture_dir(variant)
    expected = load_expected(variant)
    cache = fixture / ".cache"
    cache.mkdir(exist_ok=True)

    for tool in expected.get("build_tools_required", []):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} required to build {variant}")

    sample_name = expected.get("sample_name")
    if not sample_name:
        raise ValueError(f"expected.json for {variant} missing sample_name")
    sample = cache / sample_name

    if not sample.exists():
        build_sh = fixture / "build.sh"
        if not build_sh.exists():
            raise FileNotFoundError(f"build.sh missing for {variant}")
        env = os.environ.copy()
        env["CACHE_DIR"] = str(cache)
        env["FIXTURE_DIR"] = str(fixture)
        result = subprocess.run(
            ["bash", str(build_sh)], env=env, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"build.sh for {variant} failed: {result.stderr[-2000:]}"
            )
        if not sample.exists():
            raise RuntimeError(
                f"build.sh for {variant} did not produce {sample}"
            )

    got = _sha256(sample)
    want = expected["sample_sha256"]
    if want != "SKIP_SHA_CHECK" and got != want:
        raise AssertionError(
            f"{variant} sample sha256 mismatch: got {got}, want {want}"
        )
    return sample
