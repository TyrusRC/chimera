"""Unit tests for memory-image format detection."""
from pathlib import Path

import pytest

from chimera.model.binary import BinaryFormat, Platform, _detect_format, _guess_platform
from chimera.pipelines.common import detect_binary_format, detect_platform


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_lime_magic_detected_as_memory_lime(tmp_path):
    p = _write(tmp_path / "core", b"LiME" + b"\x00" * 100)
    assert _detect_format(p) == BinaryFormat.MEMORY_LIME


def test_emil_byte_order_also_detected(tmp_path):
    p = _write(tmp_path / "core", b"EMiL" + b"\x00" * 100)
    assert _detect_format(p) == BinaryFormat.MEMORY_LIME


def test_raw_suffix_detected_as_memory_raw(tmp_path):
    p = _write(tmp_path / "image.raw", b"\x00" * 200)
    assert _detect_format(p) == BinaryFormat.MEMORY_RAW


def test_mem_suffix_detected(tmp_path):
    p = _write(tmp_path / "image.mem", b"\x00" * 200)
    assert _detect_format(p) == BinaryFormat.MEMORY_RAW


def test_dmp_suffix_detected(tmp_path):
    p = _write(tmp_path / "image.dmp", b"\x00" * 200)
    assert _detect_format(p) == BinaryFormat.MEMORY_RAW


def test_vmem_suffix_detected(tmp_path):
    p = _write(tmp_path / "image.vmem", b"\x00" * 200)
    assert _detect_format(p) == BinaryFormat.MEMORY_RAW


def test_lime_suffix_without_magic(tmp_path):
    p = _write(tmp_path / "x.lime", b"\x00" * 200)
    assert _detect_format(p) == BinaryFormat.MEMORY_LIME


def test_pipeline_detect_binary_format_classifies_lime(tmp_path):
    p = _write(tmp_path / "core", b"LiME" + b"\x00" * 100)
    assert detect_binary_format(p) == "memory_lime"


def test_pipeline_detect_platform_routes_to_linux_memory(tmp_path):
    p = _write(tmp_path / "core", b"LiME" + b"\x00" * 100)
    assert detect_platform(p) == "linux_memory"


def test_pipeline_detect_platform_routes_raw_image(tmp_path):
    p = _write(tmp_path / "image.raw", b"\x00" * 200)
    assert detect_platform(p) == "linux_memory"


def test_guess_platform_lime():
    assert _guess_platform(BinaryFormat.MEMORY_LIME) == Platform.LINUX_MEMORY


def test_guess_platform_raw():
    assert _guess_platform(BinaryFormat.MEMORY_RAW) == Platform.LINUX_MEMORY


def test_is_memory_image_property():
    assert BinaryFormat.MEMORY_LIME.is_memory_image is True
    assert BinaryFormat.MEMORY_RAW.is_memory_image is True
    assert BinaryFormat.PE32.is_memory_image is False
    assert BinaryFormat.APK.is_memory_image is False


def test_memory_formats_are_not_mobile():
    assert BinaryFormat.MEMORY_LIME.is_mobile is False
    assert BinaryFormat.MEMORY_RAW.is_mobile is False
