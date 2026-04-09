# jcodemunch — MCP Server for AST Chunking
FROM python:3.12-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY libs/ /app/libs/
COPY services/jcodemunch/ /app/services/jcodemunch/
RUN pip install --no-cache-dir /app/libs/forge_security /app/libs/forge_telemetry /app/services/jcodemunch
CMD ["python", "-m", "jcodemunch.main"]
FROM base AS dev
CMD ["python", "-m", "jcodemunch.main", "--dev"]
