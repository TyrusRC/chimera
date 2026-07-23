"""FastAPI application — serves REST API, WebSocket, and static React build."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import os

from chimera import __version__
from chimera.api.auth import require_auth
from chimera.api.routes import system, projects, functions, strings, callgraph, devices, frida, uploads, diff, findings, annotations, decomp, ai, overlay_io, notebook, varbert as varbert_routes, flutter as flutter_routes
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
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }
    if cors_env:
        # Explicit env: comma-separated literal origins. Credentials are only
        # allowed when the operator has pinned exact origins.
        cors_kwargs["allow_origins"] = [
            o.strip() for o in cors_env.split(",") if o.strip()
        ]
        cors_kwargs["allow_credentials"] = True
    else:
        # Default: any localhost port (dev workflow), but WITHOUT credentials —
        # the API authenticates via a bearer token, not cookies, so a rebinding
        # attacker against the localhost bind can't ride an ambient session.
        cors_kwargs["allow_origin_regex"] = r"^http://localhost(:\d+)?$"
        cors_kwargs["allow_credentials"] = False
    app.add_middleware(CORSMiddleware, **cors_kwargs)

    # Bearer-token auth on every API router (no-op until CHIMERA_API_TOKEN is
    # set; see chimera.api.auth). The static SPA mount is intentionally left
    # open so the UI loads; lock the UI down at the reverse proxy if needed.
    auth = [Depends(require_auth)]

    # Register API routes
    app.include_router(system.router, dependencies=auth)
    # uploads is registered before projects so /api/projects/upload is matched
    # before any catch-all parametric route on the projects router.
    app.include_router(uploads.router, dependencies=auth)
    app.include_router(projects.router, dependencies=auth)
    app.include_router(functions.router, dependencies=auth)
    app.include_router(strings.router, dependencies=auth)
    app.include_router(callgraph.router, dependencies=auth)
    app.include_router(devices.router, dependencies=auth)
    app.include_router(frida.router, dependencies=auth)
    app.include_router(diff.router, dependencies=auth)
    app.include_router(findings.router, dependencies=auth)
    app.include_router(annotations.router, dependencies=auth)
    app.include_router(decomp.router, dependencies=auth)
    app.include_router(ai.router, dependencies=auth)
    app.include_router(overlay_io.router, dependencies=auth)
    app.include_router(notebook.router, dependencies=auth)
    app.include_router(varbert_routes.router, dependencies=auth)
    app.include_router(flutter_routes.router, dependencies=auth)
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
