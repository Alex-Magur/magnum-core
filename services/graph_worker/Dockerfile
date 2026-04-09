# forge-graph-worker — Durable State Machine
FROM python:3.12-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY libs/ /app/libs/
COPY services/graph_worker/ /app/services/graph_worker/
RUN pip install --no-cache-dir /app/libs/forge_security /app/libs/forge_storage /app/libs/forge_telemetry /app/services/graph_worker
CMD ["python", "-m", "graph_worker.main"]

FROM base AS dev
CMD ["python", "-m", "graph_worker.main", "--dev"]
