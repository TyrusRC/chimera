FROM python:3.12-slim AS base

LABEL maintainer="Chimera Project"
LABEL description="Mobile reverse engineering platform"
LABEL license="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="/usr/local/bin:/opt/ghidra:$PATH"
ENV UV_LINK_MODE=copy

# System deps (including build tools for r2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk-headless \
    wget unzip curl git jq \
    build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Radare2 — install and resolve all symlinks before cleanup
RUN git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/r2 \
    && cd /tmp/r2 && sys/install.sh \
    && find /usr/local/bin /usr/local/lib /usr/local/share -lname '/tmp/r2/*' -exec sh -c \
         'for f; do target=$(readlink -f "$f"); rm "$f"; cp -a "$target" "$f"; done' _ {} + \
    && ldconfig \
    && rm -rf /tmp/r2

# jadx — resolve latest release ZIP via GitHub API
RUN JADX_URL=$(curl -sL https://api.github.com/repos/skylot/jadx/releases/latest \
      | jq -r '.assets[] | select(.name | endswith(".zip")) | .browser_download_url' \
      | head -1) \
    && echo "Downloading jadx from: $JADX_URL" \
    && wget -q "$JADX_URL" -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx 2>/dev/null || true \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip

# Ghidra — resolve latest release ZIP via GitHub API
RUN GHIDRA_URL=$(curl -sL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
      | jq -r '.assets[] | select(.name | endswith(".zip")) | .browser_download_url' \
      | head -1) \
    && echo "Downloading Ghidra from: $GHIDRA_URL" \
    && wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip

# uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Chimera
WORKDIR /app
COPY pyproject.toml uv.lock* ./
COPY src/ src/
RUN uv sync --no-dev --frozen 2>/dev/null || uv sync --no-dev

# Test material mount point
VOLUME ["/projects", "/cache", "/data"]

ENTRYPOINT ["uv", "run", "chimera"]
CMD ["--help"]
