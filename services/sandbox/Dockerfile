# forge-sandbox — OpenSandbox (OpenShell)
FROM python:3.12-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY libs/ /app/libs/
COPY services/sandbox/ /app/services/sandbox/
RUN pip install --no-cache-dir /app/libs/forge_security /app/libs/forge_telemetry /app/services/sandbox
CMD ["python", "-m", "sandbox.main"]
FROM base AS dev
CMD ["python", "-m", "sandbox.main", "--dev"]
