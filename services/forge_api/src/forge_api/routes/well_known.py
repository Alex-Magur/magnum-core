"""Well-Known endpoints.

ADR References:
  - Б2.1: GET /.well-known/oauth-protected-resource (RFC 9728)
  - Б2.2: GET /.well-known/forge-provenance-jwks.json
  - Б14:  GET /.well-known/agent-card.json & /agent.json (Dual Discovery, Phase 5)

RFC 9728 — OAuth 2.0 Protected Resource Metadata:
  The Protected Resource Metadata document is served at:
    /.well-known/oauth-protected-resource
  It declares the issuer, JWKS URI and the audiences supported by this
  resource server, allowing clients to auto-discover the correct IdP.

Caching: responses include Cache-Control and ETag headers.
"""

from __future__ import annotations

import hashlib
import json
import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from forge_api.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["well-known"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _etag(body: bytes) -> str:
    """Compute a weak ETag from response body bytes."""
    digest = hashlib.sha256(body).hexdigest()[:16]
    return f'W/"{digest}"'


def _json_response_with_cache(
    data: dict,
    *,
    max_age: int = 3600,
) -> Response:
    """Build a JSON response with ETag and Cache-Control."""
    raw = json.dumps(data, separators=(",", ":")).encode()
    tag = _etag(raw)
    return Response(
        content=raw,
        media_type="application/json",
        headers={
            "Cache-Control": f"public, max-age={max_age}",
            "ETag": tag,
        },
    )


# ---------------------------------------------------------------------------
# RFC 9728 — OAuth 2.0 Protected Resource Metadata
# P1-AC3: GET /.well-known/oauth-protected-resource must return a valid
#          document containing issuer, jwks_uri, and be cacheable.
# ---------------------------------------------------------------------------

@router.get(
    "/.well-known/oauth-protected-resource",
    summary="OAuth 2.0 Protected Resource Metadata (RFC 9728)",
    operation_id="get_oauth_protected_resource_metadata",
    include_in_schema=True,
)
async def oauth_protected_resource_metadata(request: Request) -> Response:
    """Return the OAuth 2.0 Protected Resource Metadata document.

    Per RFC 9728 the document MUST include:
    - ``resource``     — canonical URL of this resource server
    - ``issuer``       — the authorization server issuer
    - ``jwks_uri``     — where to fetch the public signing keys
    - ``bearer_methods_supported`` — ["header"]

    The response is cacheable (max-age=3600, ETag).
    """
    base_url = str(request.base_url).rstrip("/")
    doc = {
        "resource": base_url,
        "issuer": settings.oauth_issuer,
        "jwks_uri": settings.oauth_jwks_uri,
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["forge:job:read", "forge:job:write"],
    }
    logger.debug("Serving oauth-protected-resource metadata")
    return _json_response_with_cache(doc, max_age=3600)


# ---------------------------------------------------------------------------
# Provenance JWKS — ADR Б2.2
# Separate from the OAuth JWKS; used ONLY for verifying provenance signatures.
# Published here as a placeholder endpoint; signing keys are managed by
# MCP Gateway (Phase 2). Returns a minimal well-formed JWKS document.
# ---------------------------------------------------------------------------

@router.get(
    "/.well-known/forge-provenance-jwks.json",
    summary="Forge Provenance JWKS (ADR Б2.2)",
    operation_id="get_forge_provenance_jwks",
    include_in_schema=True,
)
async def forge_provenance_jwks() -> Response:
    """Return the Forge provenance JWKS document.

    ADR Б2.2: "Gateway publishes /.well-known/forge-provenance-jwks.json
    EXCLUSIVELY for verifying provenance signatures."

    At Phase 1 the actual provenance signing keys live in MCP Gateway
    (Phase 2 block). This endpoint returns an EMPTY JWKS document so the
    URL contract is satisfied and tests can verify the endpoint exists and
    returns a well-formed body.
    """
    doc = {"keys": []}
    return _json_response_with_cache(doc, max_age=300)
