"""P1-AC4: jwt_correctness — Phase 1 acceptance test.

ADR Б16 Phase 1:
  P1-AC4 (JWT Correctness):
    When a token has wrong iss/aud or is expired.
    Then → 401 invalid_token + audit_log.

Tests use RS256 keys generated in-memory (no external IdP required).
Uses pytest-asyncio for async test functions.
httpx AsyncClient to drive the FastAPI ASGI app directly.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jose import jwt

from forge_api.auth.jwks_cache import _reset_cache_for_testing
from forge_api.main import app

pytestmark = pytest.mark.phase1

# ---------------------------------------------------------------------------
# Key generation (in-memory, test-only)
# ---------------------------------------------------------------------------

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_KID = "test-key-1"
_ISSUER = "https://idp.example.test"
_AUDIENCE = "forge-core-api"


def _make_token(
    *,
    iss: str = _ISSUER,
    aud: str = _AUDIENCE,
    job_id: str = "job-abc",
    exp_delta: int = 3600,
    kid: str = _KID,
    include_job_id: bool = True,
) -> str:
    """Build a signed RS256 JWT using the in-memory test key."""
    now = int(time.time())
    claims: dict = {
        "sub": "agent@test",
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_delta,
    }
    if include_job_id:
        claims["job_id"] = job_id

    pem = _PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_settings_and_jwks(monkeypatch, respx_mock):
    """Patch settings + JWKS endpoint to use in-memory test keys."""
    from forge_api import config

    monkeypatch.setattr(config.settings, "oauth_issuer", _ISSUER)
    monkeypatch.setattr(config.settings, "oauth_jwks_uri", "https://idp.example.test/.well-known/jwks.json")
    monkeypatch.setattr(config.settings, "oauth_audience", _AUDIENCE)

    # Build a JWKS response from the in-memory public key
    pub_numbers = _PUBLIC_KEY.public_key().public_numbers() if hasattr(_PUBLIC_KEY, "public_key") else _PUBLIC_KEY.public_numbers()
    import base64, struct

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
# Test cases  (P1-AC4)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_token_accepted(client):
    """A well-formed, in-date token with correct iss/aud/job_id is accepted."""
    token = _make_token()
    from forge_api.auth import validate_token
    from forge_api.config import settings as s

    claims = await validate_token(token, s)
    assert claims.sub == "agent@test"
    assert claims.job_id == "job-abc"
    assert claims.iss == _ISSUER


@pytest.mark.asyncio
async def test_expired_token_rejected():
    """P1-AC4: Expired token → TokenValidationError with error_code='expired_token'."""
    from forge_api.auth import TokenValidationError, validate_token
    from forge_api.config import settings as s

    token = _make_token(exp_delta=-1)   # already expired
    with pytest.raises(TokenValidationError) as exc_info:
        await validate_token(token, s)
    assert exc_info.value.error_code == "expired_token"


@pytest.mark.asyncio
async def test_wrong_issuer_rejected():
    """P1-AC4: Wrong iss → TokenValidationError."""
    from forge_api.auth import TokenValidationError, validate_token
    from forge_api.config import settings as s

    token = _make_token(iss="https://evil-idp.example")
    with pytest.raises(TokenValidationError):
        await validate_token(token, s)


@pytest.mark.asyncio
async def test_wrong_audience_rejected():
    """P1-AC4: Wrong aud → TokenValidationError."""
    from forge_api.auth import TokenValidationError, validate_token
    from forge_api.config import settings as s

    token = _make_token(aud="other-service")
    with pytest.raises(TokenValidationError):
        await validate_token(token, s)


@pytest.mark.asyncio
async def test_missing_job_id_rejected():
    """P1-AC4: Token without job_id claim → TokenValidationError."""
    from forge_api.auth import TokenValidationError, validate_token
    from forge_api.config import settings as s

    token = _make_token(include_job_id=False)
    with pytest.raises(TokenValidationError) as exc_info:
        await validate_token(token, s)
    assert "job_id" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_unknown_kid_rejected():
    """P1-AC4: Token with unknown kid → TokenValidationError (key not in JWKS)."""
    from forge_api.auth import TokenValidationError, validate_token
    from forge_api.config import settings as s

    token = _make_token(kid="unknown-kid-999")
    with pytest.raises(TokenValidationError):
        await validate_token(token, s)
