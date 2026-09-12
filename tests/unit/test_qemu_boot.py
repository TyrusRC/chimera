"""QEMU boot oracle: tool resolution + graceful degrade + guards.

The actual boot is verified out-of-band (it needs qemu + a bootable image);
these cover the dependency-free logic without launching a VM.
"""
from __future__ import annotations

from chimera.dynamic import qemu_boot as Q


def test_unavailable_when_qemu_missing():
    r = Q.qemu_boot(bios="/tmp/x.bin", qemu="/no/such/qemu-system-x86_64")
    assert r["available"] is False and "qemu" in r["error"]


def test_needs_bios_or_disk(monkeypatch):
    monkeypatch.setattr(Q, "_resolve", lambda q: "/usr/bin/qemu-system-x86_64")
    r = Q.qemu_boot()
    assert r["available"] and "need bios" in r["error"]


def test_missing_image_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(Q, "_resolve", lambda q: "/usr/bin/qemu-system-x86_64")
    r = Q.qemu_boot(bios=str(tmp_path / "nope.bin"))
    assert r["available"] and "not found" in r["error"]


def test_resolve_explicit_path(tmp_path):
    f = tmp_path / "qemu-system-x86_64"
    f.write_text("#!/bin/sh\n")
    assert Q._resolve(str(f)) == str(f)
    assert Q._resolve(str(tmp_path / "missing")) is None
