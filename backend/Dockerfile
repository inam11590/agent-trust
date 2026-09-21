# Multi-stage production Dockerfile for AgentTrust Backend
# Security controls: Non-root user (UID 10001:10001), minimal attack surface, zero embedded secrets.

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /install

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --prefix=/install -r requirements.txt


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.12/site-packages:$PYTHONPATH"

WORKDIR /app

# Copy built dependencies from builder stage
COPY --from=builder /install /install

# Install runtime PostgreSQL client library
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group (UID 10001 / GID 10001)
RUN groupadd -g 10001 agenttrust && \
    useradd -u 10001 -g agenttrust -s /bin/false -m agenttrust

# Copy application artifacts
COPY alembic ./alembic
COPY alembic.ini docker-entrypoint.sh ./
COPY app ./app

RUN chmod 0555 /app/docker-entrypoint.sh && \
    chown -R agenttrust:agenttrust /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["api"]
