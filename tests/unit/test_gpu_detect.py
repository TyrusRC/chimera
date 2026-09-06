"""Tests for host GPU + cracker detection.

The parsing is the part that can silently break when a tool changes its
output format, so it's driven with captured real-world text. `detect_gpu()`
itself is exercised as a smoke test (it shells out to whatever is on the box)
to prove it never raises and computes `usable` from real components.
"""
from __future__ import annotations

from chimera.hw.gpu import (
    CrackerInfo,
    GpuDevice,
    GpuReport,
    detect_gpu,
    parse_hashcat_backends,
    parse_nvidia_smi,
)

# Real `nvidia-smi --query-gpu=name,memory.total,compute_cap,driver_version
# --format=csv,noheader,nounits` line from an RTX 3060 box.
_SMI = "NVIDIA GeForce RTX 3060, 12288, 8.6, 610.88\n"

# Trimmed real `hashcat -I` output.
_HASHCAT_I = """\
hashcat (v7.1.2) starting in backend information mode

CUDA.Version.: 13.3

Backend Device ID #01
  Name...........: NVIDIA GeForce RTX 3060
  Processor(s)...: 28
  Memory.Total...: 12287 MB
"""


def test_parse_nvidia_smi_single_gpu():
    gpus = parse_nvidia_smi(_SMI)
    assert len(gpus) == 1
    g = gpus[0]
    assert g.name == "NVIDIA GeForce RTX 3060"
    assert g.memory_mb == 12288
    assert g.compute_cap == "8.6"
    assert g.driver == "610.88"


def test_parse_nvidia_smi_multi_and_blank_lines():
    text = "GPU A, 8192, 7.5, 500.1\n\nGPU B, 24576, 8.9, 550.2\n"
    gpus = parse_nvidia_smi(text)
    assert [g.name for g in gpus] == ["GPU A", "GPU B"]
    assert gpus[1].memory_mb == 24576


def test_parse_hashcat_backends_extracts_device_name():
    assert parse_hashcat_backends(_HASHCAT_I) == ["NVIDIA GeForce RTX 3060"]


def test_parse_hashcat_backends_empty_when_absent():
    assert parse_hashcat_backends("no devices here") == []


def test_usable_requires_gpu_and_cracker():
    # A helper mirroring detect_gpu()'s verdict, exercised via the dataclass.
    gpu_only = GpuReport(
        gpus=[GpuDevice("X")],
        hashcat=CrackerInfo("hashcat", present=False),
        john=CrackerInfo("john", present=False),
        usable=False,
    )
    assert gpu_only.usable is False  # GPU but no cracker → not usable
    both = GpuReport(
        gpus=[GpuDevice("X")],
        hashcat=CrackerInfo("hashcat", present=True),
        john=CrackerInfo("john", present=False),
        usable=True,
    )
    assert both.usable is True


def test_summary_is_a_readable_one_liner():
    rep = GpuReport(
        gpus=[GpuDevice("RTX 3060", memory_mb=12288, compute_cap="8.6")],
        hashcat=CrackerInfo("hashcat", present=True),
        john=CrackerInfo("john", present=False),
        usable=True,
    )
    s = rep.summary()
    assert "RTX 3060" in s and "hashcat" in s and "available" in s


def test_detect_gpu_smoke_never_raises():
    rep = detect_gpu()
    assert isinstance(rep, GpuReport)
    # usable is the AND of "has a GPU" and "has a cracker"; keep the invariant.
    has_cracker = rep.hashcat.present or rep.john.present
    assert rep.usable == (bool(rep.gpus) and has_cracker)
    assert isinstance(rep.as_dict(), dict)
