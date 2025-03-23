# Use multi-stage build to minimize image size
FROM python:3.10-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.10-slim
COPY --from=builder /install /usr/local

# Add non-root user for security
RUN adduser --disabled-password --gecos '' c2user

WORKDIR /app
COPY . .

# Set proper permissions
RUN chown -R c2user:c2user /app
USER c2user

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${C2_SERVER_PORT}/health || exit 1

# Default environment variables
ENV C2_SERVER_HOST=0.0.0.0
ENV C2_SERVER_PORT=443
ENV C2_SSL_CERT=/app/certs/cert.pem
ENV C2_SSL_KEY=/app/certs/key.pem
ENV C2_LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE ${C2_SERVER_PORT}

CMD ["python", "run_server.py"]