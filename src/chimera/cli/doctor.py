"""chimera.cli — doctor: exhaustive external-dependency health check.

`chimera info` (see `info.py`) is a quick glance at the handful of
backends the core `analyze` pipeline leans on. `doctor` is the
exhaustive sweep: every external tool documented in the README's
"Optional tools" section, plus environment/config that gates optional
surfaces (AI assistant key, Docker, the durable project store).

Exit code: 0 unless neither of the two core decompilers (radare2,
Ghidra) is available — without at least one of those, `chimera analyze`
cannot decompile anything, so that's the one condition worth failing a
CI/setup check on. Every other tool is genuinely optional (pipelines
skip gracefully when absent), so its absence is reported but never
fails the exit code.
"""

from __future__ import annotations

import logging
import os
import shutil

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)


# Each entry: (adapter instance, one-line install hint), grouped to
# mirror the README's "Optional tools" / backend-matrix layout.
def _adapter_groups():
    # Imported lazily (inside the command) so `chimera doctor --help`
    # doesn't pay for importing every adapter module.
    from chimera.adapters.afl import AFLAdapter
    from chimera.adapters.apktool import ApktoolAdapter
    from chimera.adapters.binquery_adapter import BinQueryAdapter
    from chimera.adapters.blutter_adapter import BlutterAdapter
    from chimera.adapters.capa_adapter import CapaAdapter
    from chimera.adapters.class_dump import ClassDumpAdapter
    from chimera.adapters.floss import FlossAdapter
    from chimera.adapters.frida_adapter import FridaAdapter
    from chimera.adapters.frida_dexdump import FridaDexdumpAdapter
    from chimera.adapters.ghidra import GhidraAdapter
    from chimera.adapters.hermes_dec import HermesDecAdapter
    from chimera.adapters.hermes_decomp import HermesDecompAdapter
    from chimera.adapters.ilspy import IlspyAdapter
    from chimera.adapters.jadx import JadxAdapter
    from chimera.adapters.mergen_adapter import MergenAdapter
    from chimera.adapters.oatdump_adapter import OatDumpAdapter
    from chimera.adapters.oxidizer_adapter import OxidizerAdapter
    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.adapters.semgrep import SemgrepAdapter
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.adapters.varbert_adapter import VarBertAdapter
    from chimera.adapters.volatility import VolatilityAdapter
    from chimera.adapters.webcrack import WebcrackAdapter
    from chimera.adapters.yara_adapter import YaraAdapter
    from chimera.adapters.yara_x_adapter import YaraXAdapter

    return [
        ("Core decompilers", [
            (Radare2Adapter(), "apt-get install radare2  (or build from github.com/radareorg/radare2)"),
            (GhidraAdapter(), "download from ghidra-sre.org and set GHIDRA_HOME"),
        ]),
        ("Java / Kotlin / Android", [
            (JadxAdapter(), "apt-get install jadx  (or github.com/skylot/jadx releases)"),
            (ApktoolAdapter(), "apt-get install apktool"),
        ]),
        ("iOS", [
            (ClassDumpAdapter(), "build from github.com/nygard/class-dump (macOS toolchain)"),
            (SwiftDemangleAdapter(), "install the Swift toolchain (swift.org)"),
        ]),
        (".NET", [
            (IlspyAdapter(), "dotnet tool install -g ilspycmd"),
        ]),
        ("Static analysis", [
            (SemgrepAdapter(), "pip install semgrep"),
            (YaraAdapter(), "pip install yara-python  (core dependency — reinstall with pip install -e .)"),
            (YaraXAdapter(), "cargo install yara-x-cli  (activate with CHIMERA_USE_YARA_X=1)"),
            (CapaAdapter(), 'pip install "chimera[capa]"'),
            (FlossAdapter(), "pip install flare-floss"),
        ]),
        ("Dynamic / fuzzing", [
            (FridaAdapter(), 'pip install "chimera[dynamic]"'),
            (FridaDexdumpAdapter(), 'pip install "chimera[dynamic]"'),
            (AFLAdapter(), "apt-get install aflplusplus  (or github.com/AFLplusplus/AFLplusplus)"),
        ]),
        ("JavaScript / React Native", [
            (WebcrackAdapter(), "npm install -g webcrack"),
            (HermesDecAdapter(), "build from github.com/bongtrop/hermes-dec"),
            (HermesDecompAdapter(), "build from github.com/SymbioticSec/hermes-decomp, or set CHIMERA_HERMES_DECOMP_BIN"),
        ]),
        ("Flutter / Dart", [
            (BlutterAdapter(), "build from github.com/worawit/blutter, or set CHIMERA_BLUTTER_BIN"),
        ]),
        ("Research add-ons", [
            (MergenAdapter(), "build from github.com/NaC-L/Mergen, or set CHIMERA_MERGEN_BIN"),
            (OxidizerAdapter(), "pip install angr"),
            (VarBertAdapter(), 'pip install "chimera[varbert]"'),
            (OatDumpAdapter(), "build oatdump2binexport (see Phrack 72:13), or set CHIMERA_OATDUMP2BINEXPORT_BIN"),
            (BinQueryAdapter(), "pip install binquery"),
        ]),
        ("Memory forensics", [
            (VolatilityAdapter(), "pip install volatility3"),
        ]),
    ]


# Plain PATH binaries with no adapter wrapper.
_BINARY_CHECKS: list[tuple[str, str]] = [
    ("upx", "apt-get install upx-ucl"),
    ("gdb", "apt-get install gdb"),
    ("qemu-aarch64", "apt-get install qemu-user qemu-user-static  — run ARM/aarch64 "
     "binaries on an x86 host; `qemu-aarch64 -cpu max` emulates ARMv9 MTE/PAuth/BTI"),
    ("dex2oat", "ships with the Android platform build tools / AOSP"),
    ("bindiff", "download from github.com/google/bindiff"),
    ("dotnet", "needed for .NET decompile (ilspy) and `chimera dotnet-trace` "
     "— install the .NET SDK from dotnet.microsoft.com"),
    ("docker", "see docs.docker.com/get-docker"),
    ("node", "needed only for the web UI dev server — see nodejs.org"),
]


@main.command()
def doctor():
    """Exhaustive external-dependency + environment health check.

    Sweeps every optional tool the README documents, reports what's
    installed vs. missing with an install hint, and flags environment
    config (AI key, Docker, durable store) as configured or not. Exits
    non-zero only if neither core decompiler (radare2, ghidra) is
    available.
    """
    click.echo("Chimera doctor")
    click.echo()

    core_ok = False
    for group_name, entries in _adapter_groups():
        click.echo(f"{group_name}:")
        for adapter, hint in entries:
            available = adapter.is_available()
            if group_name == "Core decompilers" and available:
                core_ok = True
            _print_line(adapter.name(), available, hint)
        click.echo()

    click.echo("Other tools:")
    for binary, hint in _BINARY_CHECKS:
        _print_line(binary, shutil.which(binary) is not None, hint)
    click.echo()

    click.echo("Environment:")
    _print_env_line("ANTHROPIC_API_KEY", "enables `chimera ai ...` and the SPA AI buttons")
    _print_env_line("CHIMERA_PERSIST", "opt-in durable project store (needs CHIMERA_DB_URL + Postgres)")
    _print_env_line("CHIMERA_DB_URL", "Postgres DSN for the durable store", redact=True)
    _print_env_line("GHIDRA_HOME", "required for the Ghidra backend")
    click.echo()

    if not core_ok:
        click.echo(
            "FAIL: neither radare2 nor Ghidra is available — "
            "`chimera analyze` cannot decompile anything. Install at "
            "least one (see hints above).",
            err=True,
        )
        raise SystemExit(1)

    click.echo("OK: at least one core decompiler is available.")


def _print_line(name: str, available: bool, hint: str) -> None:
    status = "available" if available else "missing"
    line = f"  {name:22} {status}"
    if not available:
        line += f"  — {hint}"
    click.echo(line)


def _print_env_line(var: str, purpose: str, redact: bool = False) -> None:
    value = os.environ.get(var)
    if value:
        shown = "set (redacted)" if redact else "set"
    else:
        shown = "unset"
    click.echo(f"  {var:22} {shown:16} — {purpose}")
