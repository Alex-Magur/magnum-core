"""Forge Core API — FastAPI Application Entrypoint.

ADR References:
  - Б1 (Deployment Topology)
  - Б2.1 (OIDC/OAuth 2.1 Resource Server)
  - Б11 (Communication Gateway & API)
  - Б14 (A2A Protocol — Dual Discovery)
"""

from fastapi import FastAPI

from forge_api.routes.well_known import router as well_known_router

app = FastAPI(
    title="Forge Core API",
    version="12.0.0",
    description="Diamond Citadel — MCP-Native, A2A & Zero-Trust LLM Code-Agent Platform",
)

# Well-known endpoints (RFC 9728, ADR Б2.2)
app.include_router(well_known_router)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "12.0.0"}
