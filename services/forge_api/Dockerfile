# forge-api — Forge Core REST API Server
FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libs first (for layer caching)
COPY libs/ /app/libs/

# Copy service code
COPY services/forge_api/ /app/services/forge_api/

# Install dependencies
RUN pip install --no-cache-dir /app/libs/forge_security \
    /app/libs/forge_storage \
    /app/libs/forge_telemetry \
    /app/libs/forge_a2a \
    /app/services/forge_api

EXPOSE 8443

CMD ["uvicorn", "forge_api.main:app", "--host", "0.0.0.0", "--port", "8443"]

# Development target
FROM base AS dev
CMD ["uvicorn", "forge_api.main:app", "--host", "0.0.0.0", "--port", "8443", "--reload"]
