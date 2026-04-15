"""FastAPI application — serves REST API, WebSocket, and static React build."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from chimera import __version__
from chimera.api.routes import system, projects, functions, strings, findings, callgraph, devices, export
from chimera.api.websocket import analysis as ws_analysis


def create_app() -> FastAPI:
    app = FastAPI(
        title="Chimera",
        description="Mobile reverse engineering platform API",
        version=__version__,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routes
    app.include_router(system.router)
    app.include_router(projects.router)
    app.include_router(functions.router)
    app.include_router(strings.router)
    app.include_router(findings.router)
    app.include_router(callgraph.router)
    app.include_router(export.router)
    app.include_router(devices.router)
    app.include_router(ws_analysis.router)

    # Serve React static build if it exists
    static_dir = Path(__file__).parent.parent.parent.parent / "web" / "dist"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


app = create_app()
