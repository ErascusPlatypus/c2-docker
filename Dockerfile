FROM python:3.10-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.10-slim
COPY --from=builder /install /usr/local

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' c2user

WORKDIR /app

COPY --chown=c2user:c2user requirements.txt ./
COPY --chown=c2user:c2user run_server.py ./
COPY --chown=c2user:c2user client ./client/
COPY --chown=c2user:c2user srvr ./srvr/
COPY --chown=c2user:c2user core ./core/
COPY --chown=c2user:c2user config ./config/

RUN mkdir -p /app/certs /app/logs \
    && chown -R c2user:c2user /app/certs /app/logs

USER c2user

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f https://localhost:${C2_SERVER_PORT}/health --insecure || exit 1

ENV C2_SERVER_HOST=0.0.0.0 \
    C2_SERVER_PORT=443 \
    C2_SSL_CERT=/app/certs/cert.pem \
    C2_SSL_KEY=/app/certs/key.pem \
    C2_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    C2_OBFUSCATION_ENABLED=true

EXPOSE ${C2_SERVER_PORT}

CMD ["python", "run_server.py"]