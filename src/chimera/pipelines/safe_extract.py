"""Zip-slip-safe archive extraction."""
from __future__ import annotations

import logging
import tarfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


class UnsafeMemberError(Exception):
    """Raised when an archive contains a member whose resolved path escapes the output dir."""


def _is_within(parent: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def safe_extract_zip(archive: Path, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "r") as zf:
        for member in zf.namelist():
            target = output_dir / member
            if not _is_within(output_dir, target):
                raise UnsafeMemberError(f"refusing extract: {member!r} escapes {output_dir!r}")
        zf.extractall(output_dir)


def safe_extract_tar(archive: Path, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r") as tf:
        for member in tf.getmembers():
            target = output_dir / member.name
            if not _is_within(output_dir, target):
                raise UnsafeMemberError(f"refusing extract: {member.name!r} escapes {output_dir!r}")
            if member.issym() or member.islnk():
                link_target = output_dir / member.name
                resolved = (link_target.parent / member.linkname).resolve()
                if not _is_within(output_dir, resolved):
                    raise UnsafeMemberError(f"refusing extract: symlink {member.name!r} -> {member.linkname!r} escapes")
        tf.extractall(output_dir)
