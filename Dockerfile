# syntax=docker/dockerfile:1.7
#
# Multi-stage build for Chimera. Targets:
#   tools       — radare2 (.deb) + jadx + Ghidra + runtime libs.
#   python-base — Python + chimera deps via pip.
#   runtime     — DEFAULT. tools + python-base + chimera CLI entrypoint.
#
# Cold build: ~5 min (was ~25 min with source-compiled r2).
# Warm build: ~30 sec — BuildKit cache mounts retain .debs and downloads.
#
# Build prod:    docker build -t chimera:latest .
# Build via compose: docker compose build chimera
# Verify tools:  docker run --rm --entrypoint bash chimera:latest -c \
#                  "r2 -v && jadx --version && ls /opt/ghidra/support/launch.sh"

ARG PYTHON_VERSION=3.12-slim

# ---------------------------------------------------------------------------
# Stage 1: tools — r2 + jadx + Ghidra on a slim Python image.
# Heavy, slow-changing. Cached aggressively.
# r2 ships an upstream .deb release — installing it is ~30s vs ~10min for a
# source compile, and the binary is identical to what the source build emits.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS tools

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="/opt/ghidra:/opt/jadx/bin:${PATH}"

ARG R2_VERSION=5.9.8
ARG JADX_VERSION=1.5.1
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILD=20250219

# Three BuildKit cache mounts:
#   /var/cache/apt + /var/lib/apt/lists — .deb cache survives clean builds
#   /downloads                          — jadx + ghidra + r2.deb downloads
# `rm -f /etc/apt/apt.conf.d/docker-clean` keeps apt from auto-wiping the
# cache after each install (Debian sets this for docker images by default).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,target=/downloads,sharing=locked \
    set -eux \
    && rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        ca-certificates libssl3 zlib1g \
        wget unzip \
        upx-ucl \
    \
    # Parallel downloads: jadx + Ghidra + r2.deb in the background, then wait.
    # `-nc` is no-clobber so cached downloads on the BuildKit volume are reused.
    && ( wget -nc -q "https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb" \
            -O /downloads/r2.deb & \
         wget -nc -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
            -O /downloads/jadx.zip & \
         wget -nc -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" \
            -O /downloads/ghidra.zip & \
         wait ) \
    \
    # r2 from upstream .deb — apt resolves transitive runtime deps for us.
    && apt-get install -y --no-install-recommends /downloads/r2.deb \
    \
    # jadx — strip Windows .bat launchers we won't run in a Linux container.
    && mkdir -p /opt/jadx \
    && unzip -q /downloads/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /opt/jadx/bin/*.bat \
    \
    # Ghidra — skip docs/ during unzip (faster + smaller layer than rm after).
    && unzip -q /downloads/ghidra.zip -d /opt -x "ghidra_*/docs/*" \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    \
    # unzip preserves zip-file mode bits but the GitHub release zip doesn't
    # always carry +x on the launchers. Set it explicitly so `ghidra` and
    # `support/launch.sh` are runnable regardless of how the artifact was
    # built upstream.
    && chmod +x /opt/ghidra/ghidraRun /opt/ghidra/support/launch.sh \
    && find /opt/ghidra/support -maxdepth 1 -name "*.sh" -exec chmod +x {} + \
    \
    # Drop transient packages. Plain `purge` (not --auto-remove) so we don't
    # accidentally yank libssl3 / zlib1g via dependency walking.
    && apt-get purge -y wget unzip \
    && apt-get clean

RUN r2 -v && jadx --version | head -1


# ---------------------------------------------------------------------------
# Stage 2: python-base — Python + chimera deps via pip.
# Built on slim Python (no external tools); copied into runtime in stage 3.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS python-base

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
# Resilient PyPI downloads — long timeout + retries handle flaky hops to
# files.pythonhosted.org without aborting the build.
ENV PIP_DEFAULT_TIMEOUT=300
ENV PIP_RETRIES=10
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# yara-python wheels for cpython 3.12 ship libyara statically, so we
# don't need libyara from apt — but we DO need a C toolchain in case
# pip falls back to source. Adding gcc here is small enough; the final
# image stage doesn't carry it.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux \
    && rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates build-essential libmagic1

WORKDIR /app

COPY pyproject.toml ./
COPY src/ src/

# BuildKit cache mount keeps wheels around between rebuilds, so a network
# wobble during one build doesn't force every dependency to re-download next
# time. The cache lives outside the image, so it doesn't bloat the layer.
# `[capa]` is intentionally NOT installed in the default image — capa pins
# vivisect/smda which clash with our own tooling. Users who want capa
# capabilities can `pip install flare-capa` inside a venv on the host or
# rebuild with `--build-arg INSTALL_CAPA=1`.
ARG INSTALL_CAPA=0
# Frida-python is part of the default image install so `chimera attach`
# works out of the box. Set INSTALL_FRIDA=0 to skip if you want a smaller
# image and don't need dynamic instrumentation.
ARG INSTALL_FRIDA=1
RUN --mount=type=cache,target=/root/.cache/pip \
    extras=""; \
    if [ "$INSTALL_CAPA" = "1" ]; then extras="${extras},capa"; fi; \
    if [ "$INSTALL_FRIDA" = "1" ]; then extras="${extras},dynamic"; fi; \
    extras="$(echo "$extras" | sed 's/^,//')"; \
    if [ -n "$extras" ]; then \
        pip install ".[${extras}]"; \
    else \
        pip install .; \
    fi


# ---------------------------------------------------------------------------
# Stage 2b: web-builder — produce the React SPA bundle.
# Node is only needed at build time; the result is a static directory of
# JS/CSS/HTML that the runtime FastAPI process serves directly.
# ---------------------------------------------------------------------------
FROM node:22-slim AS web-builder

WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund --prefer-offline

COPY web/ ./
RUN npm run build && test -f dist/index.html


# ---------------------------------------------------------------------------
# Stage 3: runtime — tools + chimera install. DEFAULT TARGET.
# ---------------------------------------------------------------------------
FROM tools AS runtime

ENV PATH="/opt/ghidra:/opt/jadx/bin:${PATH}"

WORKDIR /app

COPY --from=python-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-base /usr/local/bin/chimera /usr/local/bin/chimera
COPY --from=python-base /app /app
# server.py looks for `web/dist` two levels up from chimera/api/server.py —
# i.e. `<repo>/web/dist`. The runtime image keeps the same layout under /app
# so the StaticFiles mount finds the SPA without env-var hacks.
COPY --from=web-builder /web/dist /app/web/dist

# Sanity-check that everything we expect is present and runnable.
RUN set -eux \
    && r2 -v \
    && jadx --version \
    && test -x /opt/ghidra/support/launch.sh \
    && python -c "import yara; print('yara OK')" \
    && chimera --help >/dev/null \
    && test -f /app/web/dist/index.html

VOLUME ["/projects", "/cache", "/data"]

ENTRYPOINT ["chimera"]
CMD ["--help"]
