FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    wireshark-common \
    tcpdump \
    wget \
    curl \
    jq \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install uv and use it for Python packages
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv pip install --system --no-cache \
    mitmproxy \
    scapy \
    pyshark \
    cryptography

WORKDIR /openmix

# Data directory is mounted as a volume
VOLUME ["/openmix/data"]

# Analysis scripts are copied in
COPY scripts/ /openmix/scripts/

ENTRYPOINT ["/bin/bash"]
