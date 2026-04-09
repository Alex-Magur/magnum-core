"""P1-AC7: oauth_binding — Phase 1 acceptance test.

ADR Б16 Phase 1:
  P1-AC7 (OAuth Binding Test):
    When token has `job_id` NOT matching the active request `job_id`.
    Then → reject (403) + audit_log entry.

Tests verify the full FastAPI layer: a protected route using `require_auth`
dependency on a path with {job_id} parameter.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from jose import jwt

from forge_api.auth import TokenClaims, require_auth
from forge_api.auth.jwks_cache import _reset_cache_for_testing
from forge_api.main import app

pytestmark = pytest.mark.phase1

# ---------------------------------------------------------------------------
# In-memory keypair (same pattern as test_jwt_correctness)
# ---------------------------------------------------------------------------

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_KID = "binding-test-key"
_ISSUER = "https://idp.example.test"
_AUDIENCE = "forge-core-api"


def _make_token(job_id: str = "job-correct") -> str:
    now = int(time.time())
    pem = _PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    claims = {
        "sub": "agent@test",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "job_id": job_id,
    }
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": _KID})


# ---------------------------------------------------------------------------
# Register a test-only protected route (idempotent — checked before adding)
# ---------------------------------------------------------------------------

_BINDING_ROUTE_PATH = "/test-binding/jobs/{job_id}/status"

# Only add the route once (guard against module re-import in test session)
_existing_routes = {r.path for r in app.routes if hasattr(r, "path")}
if _BINDING_ROUTE_PATH not in _existing_routes:
    @app.get(_BINDING_ROUTE_PATH, include_in_schema=False)
    async def _protected_job_status(
        job_id: str,
        claims: TokenClaims = Depends(require_auth),
    ) -> dict:
        return {"job_id": job_id, "status": "ok"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_settings_and_jwks(monkeypatch, respx_mock):
    from forge_api import config

    monkeypatch.setattr(config.settings, "oauth_issuer", _ISSUER)
    monkeypatch.setattr(
        config.settings,
        "oauth_jwks_uri",
        "https://idp.example.test/.well-known/jwks.json",
    )
    monkeypatch.setattr(config.settings, "oauth_audience", _AUDIENCE)

    pub_numbers = _PUBLIC_KEY.public_numbers()
    import base64

    def _b64(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    jwks_doc = {
        "keys": [
            {
                "kty": "RSA",
                "kid": _KID,
                "use": "sig",
                "alg": "RS256",
                "n": _b64(pub_numbers.n),
                "e": _b64(pub_numbers.e),
            }
        ]
    }
    respx_mock.get("https://idp.example.test/.well-known/jwks.json").respond(
        200, json=jwks_doc
    )
    _reset_cache_for_testing()
    yield
    _reset_cache_for_testing()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# P1-AC7 test cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binding_match_accepted(client):
    """Token job_id matches path job_id → 200 OK."""
    token = _make_token(job_id="job-xyz")
    resp = await client.get(
        "/test-binding/jobs/job-xyz/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["job_id"] == "job-xyz"


@pytest.mark.asyncio
async def test_binding_mismatch_rejected_403(client):
    """P1-AC7: Token job_id != path job_id → 403 Forbidden."""
    token = _make_token(job_id="job-correct")
    resp = await client.get(
        "/test-binding/jobs/job-wrong/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_binding_mismatch_detail_contains_mismatch(client):
    """403 response body references the mismatch for auditability."""
    token = _make_token(job_id="job-aaa")
    resp = await client.get(
        "/test-binding/jobs/job-bbb/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    detail = resp.json().get("detail", "")
    # Detail must reference both ids or at least "job_id"
    assert "job" in detail.lower()


@pytest.mark.asyncio
async def test_no_auth_header_returns_401(client):
    """Missing Authorization header → 401."""
    resp = await client.get("/test-binding/jobs/job-xyz/status")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_returns_401(client):
    """Garbage token string → 401."""
    resp = await client.get(
        "/test-binding/jobs/job-xyz/status",
        headers={"Authorization": "Bearer not.a.real.jwt"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_verify_token_binding_unit():
    """Unit test: verify_token_binding raises TokenBindingError on mismatch."""
    from forge_api.auth import TokenBindingError, TokenClaims, verify_token_binding

    claims = TokenClaims(
        sub="agent",
        iss=_ISSUER,
        aud=_AUDIENCE,
        exp=int(time.time()) + 3600,
        job_id="job-right",
    )
    # Match → no exception
    await verify_token_binding(claims, "job-right")

    # Mismatch → TokenBindingError
    with pytest.raises(TokenBindingError):
        await verify_token_binding(claims, "job-wrong")
