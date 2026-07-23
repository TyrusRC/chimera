"""chimera.cli — serve cmd commands."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.option("--host", default="127.0.0.1",
              help="Bind host (default localhost; use 0.0.0.0 to expose)")
@click.option("--port", default=8080, help="Bind port")
def serve(host: str, port: int):
    """Start the Chimera web UI server."""
    import os
    import uvicorn
    if host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("CHIMERA_API_TOKEN"):
        click.secho(
            "WARNING: binding to a non-localhost interface without "
            "CHIMERA_API_TOKEN set — the API (including device/Frida code "
            "execution) will be reachable UNAUTHENTICATED. Set CHIMERA_API_TOKEN.",
            fg="red", err=True,
        )
    click.echo(f"Chimera v{__version__} — starting web UI on http://{host}:{port}")
    uvicorn.run("chimera.api.server:app", host=host, port=port, reload=False)



@main.command()
@click.option("--cache-dir", type=click.Path(), default=None,
              help="Cache root to browse (default: ./chimera_cache)")
def tui(cache_dir: str | None):
    """Launch the Chimera TUI — browse analysis results and devices."""
    from chimera.tui.app import run_tui
    run_tui(Path(cache_dir) if cache_dir else None)



@main.command()
def mcp():
    """Start the Chimera MCP server (for Claude Code / LLM integration)."""
    from chimera.mcp_server import main as mcp_main
    click.echo("Starting Chimera MCP server...")
    asyncio.run(mcp_main())
