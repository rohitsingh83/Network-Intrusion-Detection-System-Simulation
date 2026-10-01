# ==============================================================================
# Network Intrusion Detection System (IDS) Simulation - Production Dockerfile
# Multi-stage build for optimal image size, security, and reproducibility.
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Dependencies
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install compilation prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install dependencies into isolated wheels directory
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt


# ------------------------------------------------------------------------------
# Stage 2: Minimal Runtime Environment
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runner

WORKDIR /app

# Install curl for healthcheck validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install pre-built wheels from builder stage
COPY --from=builder /build/wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Create an unprivileged user for security hardening
RUN groupadd -g 10001 idsgroup && \
    useradd -u 10001 -g idsgroup -s /bin/bash -m idsuser

# Create necessary directories with correct permissions
RUN mkdir -p /app/data /app/models /app/reports /app/screenshots && \
    chown -R idsuser:idsgroup /app

# Copy application source code
COPY --chown=idsuser:idsgroup ids /app/ids
COPY --chown=idsuser:idsgroup ml /app/ml
COPY --chown=idsuser:idsgroup backend /app/backend
COPY --chown=idsuser:idsgroup simulator /app/simulator
COPY --chown=idsuser:idsgroup data /app/data
COPY --chown=idsuser:idsgroup models /app/models
COPY --chown=idsuser:idsgroup run.py /app/run.py
COPY --chown=idsuser:idsgroup .env.example /app/.env

# Switch to non-root user
USER idsuser

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0

# Expose API and dashboard port
EXPOSE 8000

# Docker healthcheck querying /api/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Default execution entrypoint
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
