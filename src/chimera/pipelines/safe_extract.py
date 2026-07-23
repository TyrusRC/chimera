"""Zip-slip-safe, decompression-bomb-resistant archive extraction."""
from __future__ import annotations

import logging
import os
import stat
import tarfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "")) or default
    except ValueError:
        return default


# Bomb-resistance caps (override via env). An APK/IPA is a zip; these bound the
# blast radius of a maliciously-crafted archive (42.zip-style) before extraction.
MAX_TOTAL_BYTES = _env_int("CHIMERA_EXTRACT_MAX_TOTAL_MB", 4096) * 1024 * 1024
MAX_MEMBER_BYTES = _env_int("CHIMERA_EXTRACT_MAX_MEMBER_MB", 1024) * 1024 * 1024
MAX_MEMBERS = _env_int("CHIMERA_EXTRACT_MAX_MEMBERS", 100_000)


class UnsafeMemberError(Exception):
    """Raised when an archive member escapes the output dir."""


class ArchiveTooLargeError(Exception):
    """Raised when an archive's declared uncompressed size exceeds the caps."""


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
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ArchiveTooLargeError(
                f"archive has {len(infos)} members > cap {MAX_MEMBERS}")
        total = 0
        for info in infos:
            target = output_dir / info.filename
            if not _is_within(output_dir, target):
                raise UnsafeMemberError(
                    f"refusing extract: {info.filename!r} escapes {output_dir!r}")
            # A zip stores symlinks via the unix mode in external_attr; a symlink
            # member's "content" is its target path, so zip-slip alone misses it.
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeMemberError(
                    f"refusing extract: {info.filename!r} is a symlink")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ArchiveTooLargeError(
                    f"member {info.filename!r} is {info.file_size} bytes "
                    f"> cap {MAX_MEMBER_BYTES}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ArchiveTooLargeError(
                    f"uncompressed size exceeds cap {MAX_TOTAL_BYTES} bytes")
        zf.extractall(output_dir)


def safe_extract_tar(archive: Path, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r") as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ArchiveTooLargeError(
                f"archive has {len(members)} members > cap {MAX_MEMBERS}")
        total = 0
        for member in members:
            target = output_dir / member.name
            if not _is_within(output_dir, target):
                raise UnsafeMemberError(f"refusing extract: {member.name!r} escapes {output_dir!r}")
            if member.issym() or member.islnk():
                link_target = output_dir / member.name
                resolved = (link_target.parent / member.linkname).resolve()
                if not _is_within(output_dir, resolved):
                    raise UnsafeMemberError(f"refusing extract: symlink {member.name!r} -> {member.linkname!r} escapes")
            if member.size > MAX_MEMBER_BYTES:
                raise ArchiveTooLargeError(
                    f"member {member.name!r} is {member.size} bytes > cap {MAX_MEMBER_BYTES}")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ArchiveTooLargeError(
                    f"uncompressed size exceeds cap {MAX_TOTAL_BYTES} bytes")
        tf.extractall(output_dir)
