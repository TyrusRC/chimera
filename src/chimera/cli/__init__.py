"""Chimera CLI — command-line interface for desktop + mobile RE.

This package replaces the previous single-file `chimera/cli.py` (2400+
lines, ~25 commands) with one module per command group. The top-level
Click group `main` lives in `chimera.cli._root` and is re-exported here
so that `chimera = "chimera.cli:main"` in pyproject.toml keeps working
without changes.

Each subcommand module is imported below so its `@main.command(...)`
decorators run at import time and register the command. Adding a new
command means: write a new submodule, then add one import line here.

Backwards-compat re-exports: a few helpers (`_parse_rename_json`) are
re-exported at the top level because the test suite imports them from
`chimera.cli` directly. New code should import from the submodule.
"""

from __future__ import annotations

from chimera.cli._root import main

# Register subcommands via decorator side effects. Within each module the
# splitter ordered functions by source position so @group.command()
# always runs after the @group() it decorates onto.
from chimera.cli import (  # noqa: F401  — import for decorator side effects
    _common,
    ai_cmd,
    analyze,
    android_sim_cmd,
    attach_cmd,
    classify_cmd,
    devices_cmd,
    diff_cmd,
    flutter_cmd,
    frida_cmd,
    gdb_export_cmd,
    hermes_cmd,
    imports_cmd,
    info,
    ioc_cmd,
    jni_cmd,
    manifest_cmd,
    memory_cmd,
    overlay_cmd,
    patch_cmd,
    persistence_cmd,
    protection,
    report_cmd,
    sdks_cmd,
    serve_cmd,
    unpack_cmd,
    varbert_cmd,
    vmp_cmd,
    yara_cmd,
)

# Register the database CLI group (defined in chimera/cli_db.py — separate
# from this package because db ops aren't analyst-facing).
from chimera.cli_db import db_cli

main.add_command(db_cli)

# Backwards-compat re-exports the test suite expects to find on
# `chimera.cli` directly. Keep these to a minimum — new code should import
# from the submodule.
from chimera.cli.ai_cmd import _parse_rename_json  # noqa: E402, F401
from chimera.cli.gdb_export_cmd import (  # noqa: E402, F401
    _emit_gdbinit,
    _sanitise_gdb_var,
)
from chimera.cli._common import _load_cache_and_sha  # noqa: E402, F401

__all__ = [
    "main",
    "_parse_rename_json",
    "_emit_gdbinit",
    "_sanitise_gdb_var",
    "_load_cache_and_sha",
]
