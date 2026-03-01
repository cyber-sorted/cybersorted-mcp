# ZAP Worker Container
# Runs OWASP ZAP daemon + Python agent in a single ephemeral container.
# Launched by the MCP server's Docker dispatcher for each scan job.

FROM ghcr.io/zaproxy/zaproxy:stable AS base

USER root

# Install Python 3 and pip (ZAP image is Debian-based)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install Python dependencies in a venv (avoids externally-managed-environment error)
COPY requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Update PATH so venv Python is used
ENV PATH="/app/venv/bin:$PATH"

# ZAP defaults
ENV ZAP_API_KEY=cybersorted-scanner-key
ENV ZAP_HOST=localhost
ENV ZAP_PORT=8080

ENTRYPOINT ["/app/entrypoint.sh"]
