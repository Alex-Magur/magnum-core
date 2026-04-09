"""P1-AC3: oauth_metadata — Phase 1 acceptance test.

ADR Б16 Phase 1:
  P1-AC3 (OAuth Metadata):
    When GET /.well-known/oauth-protected-resource
    Then the response is valid, contains issuer + jwks_uri, and is cacheable
         (Cache-Control + ETag headers present).

Tests drive the FastAPI ASGI app via httpx AsyncClient (no real network).
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from forge_api.main import app

pytestmark = pytest.mark.phase1

_ISSUER = "https://idp.example.test"
_JWKS_URI = "https://idp.example.test/.well-known/jwks.json"


@pytest.fixture(autouse=True)
def patch_settings(monkeypatch):
    """Set known, deterministic values in settings for assertion."""
    from forge_api import config
    monkeypatch.setattr(config.settings, "oauth_issuer", _ISSUER)
    monkeypatch.setattr(config.settings, "oauth_jwks_uri", _JWKS_URI)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# P1-AC3 test cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oauth_protected_resource_returns_200(client):
    """GET /.well-known/oauth-protected-resource → HTTP 200."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_oauth_protected_resource_contains_issuer(client):
    """Response body contains the configured issuer."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    body = resp.json()
    assert body["issuer"] == _ISSUER


@pytest.mark.asyncio
async def test_oauth_protected_resource_contains_jwks_uri(client):
    """Response body contains jwks_uri."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    body = resp.json()
    assert body["jwks_uri"] == _JWKS_URI


@pytest.mark.asyncio
async def test_oauth_protected_resource_contains_bearer_methods(client):
    """Response declares bearer_methods_supported."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    body = resp.json()
    assert "bearer_methods_supported" in body
    assert "header" in body["bearer_methods_supported"]


@pytest.mark.asyncio
async def test_oauth_protected_resource_is_cacheable(client):
    """Response includes Cache-Control and ETag headers (cacheable per RFC 9728)."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    assert "cache-control" in resp.headers
    assert "max-age" in resp.headers["cache-control"]
    assert "etag" in resp.headers


@pytest.mark.asyncio
async def test_oauth_protected_resource_content_type_json(client):
    """Response Content-Type is application/json."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    assert "application/json" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_provenance_jwks_endpoint_exists(client):
    """GET /.well-known/forge-provenance-jwks.json → 200 with keys array (ADR Б2.2)."""
    resp = await client.get("/.well-known/forge-provenance-jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "keys" in body
    assert isinstance(body["keys"], list)
