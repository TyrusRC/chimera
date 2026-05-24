"""FastAPI application — serves REST API, WebSocket, and static React build."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import os

from chimera import __version__
from chimera.api.routes import system, projects, functions, strings, callgraph, devices, frida, uploads, diff, findings, annotations, decomp
from chimera.api.websocket import analysis as ws_analysis, frida as ws_frida
from chimera.device.manager import shutdown_all


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    await shutdown_all()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Chimera",
        description="Mobile reverse engineering platform API",
        version=__version__,
        lifespan=_lifespan,
    )

    cors_env = os.environ.get("CHIMERA_CORS_ORIGINS")
    cors_kwargs: dict = {
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }
    if cors_env:
        # Explicit env: comma-separated literal origins
        cors_kwargs["allow_origins"] = [
            o.strip() for o in cors_env.split(",") if o.strip()
        ]
    else:
        # Default: any localhost port (dev workflow); production must set the env
        cors_kwargs["allow_origin_regex"] = r"^http://localhost(:\d+)?$"
    app.add_middleware(CORSMiddleware, **cors_kwargs)

    # Register API routes
    app.include_router(system.router)
    # uploads is registered before projects so /api/projects/upload is matched
    # before any catch-all parametric route on the projects router.
    app.include_router(uploads.router)
    app.include_router(projects.router)
    app.include_router(functions.router)
    app.include_router(strings.router)
    app.include_router(callgraph.router)
    app.include_router(devices.router)
    app.include_router(frida.router)
    app.include_router(diff.router)
    app.include_router(findings.router)
    app.include_router(annotations.router)
    app.include_router(decomp.router)
    app.include_router(ws_analysis.router)
    app.include_router(ws_frida.router)

    # Serve React static build if it exists. Try, in order:
    #   1. $CHIMERA_WEB_DIST (explicit override)
    #   2. <repo>/web/dist  — when chimera is installed editably from source
    #   3. /app/web/dist    — the Docker runtime layout
    #   4. <cwd>/web/dist   — when serve is run from the repo root
    static_candidates: list[Path] = []
    env_override = os.environ.get("CHIMERA_WEB_DIST")
    if env_override:
        static_candidates.append(Path(env_override))
    static_candidates += [
        Path(__file__).parent.parent.parent.parent / "web" / "dist",
        Path("/app/web/dist"),
        Path.cwd() / "web" / "dist",
    ]
    for static_dir in static_candidates:
        if static_dir.exists() and static_dir.is_dir():
            app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
            break

    return app


app = create_app()
