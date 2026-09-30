#!/usr/bin/env bash
# Thin retry wrapper around `chimera mcp` for the Claude Code MCP client.
#
# The client attempts exactly one connection at session start and never
# retries — if that attempt lands while .venv is mid-(re)provision (e.g. a
# python-version swap via `uv venv`), `chimera mcp` fails with
# ModuleNotFoundError and the server is marked dead (CONNECTION_CLOSED) for
# the rest of the session, even though .venv finishes seconds later and the
# CLI works fine from then on. Retry the readiness check here instead.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for _ in 1 2 3 4 5; do
    "$ROOT/.venv/bin/python" -c "import chimera" 2>/dev/null && break
    sleep 1
done

exec "$ROOT/.venv/bin/chimera" mcp
