# syntax=docker/dockerfile:1.7
#
# Multi-stage build for Chimera. Targets:
#   r2-builder  — throwaway. Compiles radare2 with full toolchain.
#   tools       — radare2 (artifact-copied) + jadx + Ghidra + runtime libs.
#   python-base — Python + chimera deps via pip.
#   runtime     — DEFAULT. tools + python-base + chimera CLI entrypoint.
#
# The builder pattern keeps build-essential / libssl-dev / git out of the
# final image — only compiled r2 binaries are copied into `tools`.
#
# Build prod:    docker build -t chimera:latest .
# Build via compose: docker compose build chimera
# Verify tools:  docker run --rm --entrypoint bash chimera:latest -c \
#                  "r2 -v && jadx --version && ls /opt/ghidra/support/launch.sh"

ARG PYTHON_VERSION=3.12-slim

# ---------------------------------------------------------------------------
# Stage 1: r2-builder — throwaway. Compiles radare2 from source.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS r2-builder

ENV DEBIAN_FRONTEND=noninteractive
ARG R2_VERSION=5.9.8

RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth=1 --branch "${R2_VERSION}" \
        https://github.com/radareorg/radare2.git /tmp/r2 \
    && cd /tmp/r2 && sys/install.sh \
    # Dereference symlinks pointing at /tmp/r2 so the source tree can be
    # removed without orphaning files we just installed under /usr/local.
    && find /usr/local/bin /usr/local/lib /usr/local/share \
        -lname '/tmp/r2/*' -exec sh -c \
         'for f; do target=$(readlink -f "$f"); rm "$f"; cp -a "$target" "$f"; done' _ {} +


# ---------------------------------------------------------------------------
# Stage 2: tools — r2 + jadx + Ghidra on a slim Python image.
# Heavy, slow-changing. Cached aggressively.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS tools

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="/usr/local/bin:/opt/ghidra:${PATH}"

ARG JADX_VERSION=1.5.1
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILD=20250219

# Install runtime libs Ghidra/jadx need + transient downloaders (wget, unzip),
# fetch jadx + Ghidra, then purge the transient packages in the same RUN so
# the layer stays tight. libssl3 / zlib1g are kept because radare2 (copied
# from r2-builder below) links against them at runtime.
RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        ca-certificates libssl3 zlib1g \
        wget unzip \
    \
    # jadx — strip Windows .bat launchers we won't run in a Linux container.
    && wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip /opt/jadx/bin/*.bat \
    \
    # Ghidra — drop docs/ since headless analysis doesn't need them.
    && wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm -rf /tmp/ghidra.zip /opt/ghidra/docs \
    \
    # Drop transient packages. Plain `purge` (not --auto-remove) so we don't
    # accidentally yank libssl3 / zlib1g via dependency walking.
    && apt-get purge -y wget unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Pull compiled radare2 artifacts from the builder stage.
COPY --from=r2-builder /usr/local/bin/     /usr/local/bin/
COPY --from=r2-builder /usr/local/lib/     /usr/local/lib/
COPY --from=r2-builder /usr/local/share/   /usr/local/share/
COPY --from=r2-builder /usr/local/include/ /usr/local/include/

RUN ldconfig && r2 -v


# ---------------------------------------------------------------------------
# Stage 3: python-base — Python + chimera deps via pip.
# Built on slim Python (no external tools); copied into runtime in stage 4.
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

RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY src/ src/

# BuildKit cache mount keeps wheels around between rebuilds, so a network
# wobble during one build doesn't force every dependency to re-download next
# time. The cache lives outside the image, so it doesn't bloat the layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install .


# ---------------------------------------------------------------------------
# Stage 4: runtime — tools + chimera install. DEFAULT TARGET.
# ---------------------------------------------------------------------------
FROM tools AS runtime

ENV PATH="/usr/local/bin:/opt/ghidra:${PATH}"

WORKDIR /app

COPY --from=python-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-base /usr/local/bin/chimera /usr/local/bin/chimera
COPY --from=python-base /app /app

# Sanity-check that everything we expect is present and runnable.
RUN set -eux \
    && r2 -v \
    && jadx --version \
    && test -x /opt/ghidra/support/launch.sh \
    && chimera --help >/dev/null

VOLUME ["/projects", "/cache", "/data"]

ENTRYPOINT ["chimera"]
CMD ["--help"]
