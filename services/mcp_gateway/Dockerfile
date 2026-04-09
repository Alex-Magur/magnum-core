# forge-mcp-gateway — MCP Gateway with OAuth 2.1
FROM python:3.12-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY libs/ /app/libs/
COPY services/mcp_gateway/ /app/services/mcp_gateway/
RUN pip install --no-cache-dir /app/libs/forge_security /app/libs/forge_telemetry /app/services/mcp_gateway
CMD ["uvicorn", "mcp_gateway.main:app", "--host", "0.0.0.0", "--port", "8443"]
FROM base AS dev
CMD ["uvicorn", "mcp_gateway.main:app", "--host", "0.0.0.0", "--port", "8443", "--reload"]
