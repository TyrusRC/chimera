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


_POSIX_PATH_PREFIX = None  # Cache for whether to use /mnt/ or /c


def _detect_bash_env() -> str:
    """Detect if bash is WSL2 (returns '/mnt') or Git Bash (returns '')."""
    global _POSIX_PATH_PREFIX
    if _POSIX_PATH_PREFIX is not None:
        return _POSIX_PATH_PREFIX

    # Test by running a bash command to check /mnt/c
    result = subprocess.run(
        ["bash", "-c", "[ -d /mnt/c ] && echo wsl2 || echo gitbash"],
        capture_output=True, text=True,
    )
    if "wsl2" in result.stdout:
        _POSIX_PATH_PREFIX = "/mnt"
    else:
        _POSIX_PATH_PREFIX = ""
    return _POSIX_PATH_PREFIX


def _to_posix_path(p: Path | str) -> str:
    """Convert Windows path to POSIX path for bash (Git Bash or WSL2)."""
    s = str(p)
    if os.name == "nt":  # Windows
        prefix = _detect_bash_env()
        if prefix == "/mnt":
            # WSL2: use /mnt/c instead of /c
            s = s.replace("\\", "/").replace("C:", "/mnt/c").replace("D:", "/mnt/d")
        else:
            # Git Bash: use /c
            s = s.replace("\\", "/").replace("C:", "/c").replace("D:", "/d")
    return s


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
        if shutil.which("bash") is None:
            pytest.skip(f"bash required to run build.sh for {variant}")
        env = os.environ.copy()
        cache_posix = _to_posix_path(cache)
        fixture_posix = _to_posix_path(fixture)
        build_sh_posix = _to_posix_path(build_sh)
        # On Windows, use bash -c to ensure environment variables are properly set
        if os.name == "nt":
            cmd = f'CACHE_DIR="{cache_posix}" FIXTURE_DIR="{fixture_posix}" bash "{build_sh_posix}"'
            result = subprocess.run(
                ["bash", "-c", cmd], env=env, capture_output=True, text=True
            )
        else:
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
