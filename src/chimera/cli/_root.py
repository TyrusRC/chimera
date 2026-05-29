"""Root Click group for the chimera CLI.

This is the single source of truth for the top-level `main` group. Every
subcommand module (`chimera.cli.analyze`, `chimera.cli.diff_cmd`, …)
imports `main` from here and decorates its commands onto it. Import
order is managed in `chimera/cli/__init__.py`.

Kept separate from `__init__.py` so the subcommand modules can import
`main` without creating a circular dependency back through the package
init.
"""

from __future__ import annotations

import logging

import click

from chimera import __version__


@click.group()
@click.version_option(version=__version__, prog_name="chimera")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def main(verbose: bool):
    """Chimera — Reverse engineering platform. Many backends, one beast."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
