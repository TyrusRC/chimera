# syntax=docker/dockerfile:1.7
#
# Multi-stage build for Chimera. Targets:
#   tools       — heavyweight external binaries (radare2, jadx, Ghidra)
#   python-base — Python + chimera deps (no external tools)
#   runtime     — DEFAULT. tools + python-base + chimera CLI entrypoint
#
# Build prod:    docker build -t chimera:latest .
# Build via compose: docker compose build chimera
# Verify tools:  docker run --rm --entrypoint bash chimera:latest -c \
#                  "r2 -v && jadx --version && ls /opt/ghidra/support/launch.sh"

ARG PYTHON_VERSION=3.12-slim

# ---------------------------------------------------------------------------
# Stage 1: tools — radare2 + jadx + Ghidra
# Heavy, slow-changing. Cached aggressively.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS tools

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="/usr/local/bin:/opt/ghidra:${PATH}"

# Pinned external versions (override via --build-arg if needed).
ARG R2_VERSION=5.9.8
ARG JADX_VERSION=1.5.1
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILD=20250219

RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        wget unzip curl git ca-certificates \
        build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# radare2 — pinned tag, then dereference symlinks so /tmp/r2 can be removed cleanly.
RUN set -eux \
    && git clone --depth=1 --branch "${R2_VERSION}" https://github.com/radareorg/radare2.git /tmp/r2 \
    && cd /tmp/r2 && sys/install.sh \
    && find /usr/local/bin /usr/local/lib /usr/local/share -lname '/tmp/r2/*' -exec sh -c \
         'for f; do target=$(readlink -f "$f"); rm "$f"; cp -a "$target" "$f"; done' _ {} + \
    && ldconfig \
    && rm -rf /tmp/r2

# jadx — pinned release.
RUN set -eux \
    && wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip

# Ghidra — pinned release.
RUN set -eux \
    && wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm -f /tmp/ghidra.zip


# ---------------------------------------------------------------------------
# Stage 2: python-base — Python + chimera deps via pip.
# Built on slim Python (no external tools); copied into runtime in stage 3.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS python-base

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir .


# ---------------------------------------------------------------------------
# Stage 3: runtime — tools + chimera install. DEFAULT TARGET.
# ---------------------------------------------------------------------------
FROM tools AS runtime

ENV PATH="/usr/local/bin:/opt/ghidra:${PATH}"

WORKDIR /app

COPY --from=python-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-base /usr/local/bin/chimera /usr/local/bin/chimera
COPY --from=python-base /app /app

# Sanity-check that the tools-stage binaries survived the layer copy.
RUN set -eux \
    && r2 -v \
    && jadx --version \
    && test -x /opt/ghidra/support/launch.sh \
    && chimera --help >/dev/null

VOLUME ["/projects", "/cache", "/data"]

ENTRYPOINT ["chimera"]
CMD ["--help"]
