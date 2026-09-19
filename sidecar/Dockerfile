# Production-grade minimal container for AgentTrust Sidecar (Step 23)
# Non-root, read-only root filesystem compatible, zero embedded secrets.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir fastapi uvicorn cryptography pydantic httpx

# Create unprivileged user with fixed UID/GID
RUN groupadd -g 10001 agenttrust && \
    useradd -u 10001 -g agenttrust -s /bin/false -m agenttrust

# Copy sidecar code and required backend library modules
COPY sidecar /app/sidecar
RUN mkdir -p /app/.sidecar_keys /app/.sidecar_cache && \
    chown -R agenttrust:agenttrust /app

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "sidecar.main:app", "--host", "0.0.0.0", "--port", "8080"]
