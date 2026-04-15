FROM python:3.12-slim

LABEL maintainer="Chimera Project"
LABEL description="Mobile reverse engineering platform"
LABEL license="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_HOME=/opt/ghidra

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    wget unzip curl git \
    && rm -rf /var/lib/apt/lists/*

# Radare2
RUN git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/r2 \
    && cd /tmp/r2 && sys/install.sh \
    && rm -rf /tmp/r2

# jadx
RUN wget -q https://github.com/skylot/jadx/releases/latest/download/jadx-nightly.zip \
    -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Ghidra
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3_build/ghidra_11.3_PUBLIC_20250108.zip \
    -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip

# Chimera
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

# Volumes
VOLUME ["/projects", "/cache"]

ENTRYPOINT ["chimera"]
CMD ["--help"]
