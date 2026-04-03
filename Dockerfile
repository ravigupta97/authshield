# =============================================================================
# AuthShield — Dockerfile
# Multi-stage build: keeps the final image lean by separating build-time
# dependencies (pip wheel compilation) from the runtime layer.
# =============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
# Installs and compiles all Python wheels into /wheels.
# This stage is discarded in the final image.
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps only needed for compilation (e.g. asyncpg C extension, Pillow)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Only the pre-built wheels are copied here — no compiler, no build tools.
FROM python:3.11-slim AS runtime

# Runtime system dependency for asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user — never run production apps as root
RUN groupadd --gid 1001 appuser && \
    useradd  --uid 1001 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Install pre-built wheels (no internet access needed at this stage)
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels

# Copy application source
COPY --chown=appuser:appuser . .

# Drop privileges
USER appuser

# Expose the port defined in config (default 8000)
EXPOSE 8000

# Health check — Docker will show "healthy" / "unhealthy" in `docker ps`
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

# Start Uvicorn.
# --workers is kept at 1 here; scale horizontally via docker-compose replicas
# or a Kubernetes Deployment rather than multiple in-process workers.
CMD alembic upgrade head && \
    python -m app.db.seed && \
    uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level info \
    --proxy-headers \
    --forwarded-allow-ips "*"
