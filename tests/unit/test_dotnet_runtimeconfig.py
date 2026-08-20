"""Runtimeconfig shim that lets a .NET Framework assembly run under Core."""
from __future__ import annotations

import json

from chimera.dotnet.runtimeconfig import build_runtimeconfig


def test_shim_targets_the_installed_core_runtime():
    cfg = json.loads(build_runtimeconfig("6.0.8"))
    fw = cfg["runtimeOptions"]["framework"]
    assert fw["name"] == "Microsoft.NETCore.App"
    assert fw["version"] == "6.0.8"


def test_shim_pins_major_when_given_a_bare_major():
    cfg = json.loads(build_runtimeconfig("8"))
    assert cfg["runtimeOptions"]["framework"]["version"] == "8.0.0"


def test_shim_disables_tiered_compilation_for_determinism():
    cfg = json.loads(build_runtimeconfig("6.0.8"))
    props = cfg["runtimeOptions"]["configProperties"]
    assert props["System.Runtime.TieredCompilation"] is False


def test_shim_rolls_forward_to_a_newer_patch():
    cfg = json.loads(build_runtimeconfig("6.0.8"))
    assert cfg["runtimeOptions"]["rollForward"] == "LatestMinor"


def test_shim_is_valid_json():
    # Must parse and round-trip — it is written next to the assembly.
    text = build_runtimeconfig("6.0.8")
    assert json.loads(text) == json.loads(text)
