FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN addgroup --system agenttrust && adduser --system --ingroup agenttrust --home /app agenttrust
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic ./alembic
COPY alembic.ini docker-entrypoint.sh ./
COPY app ./app
RUN chmod 0555 /app/docker-entrypoint.sh && chown -R agenttrust:agenttrust /app

USER agenttrust
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)" || exit 1
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["api"]
