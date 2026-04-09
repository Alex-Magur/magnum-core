"""OAuth 2.1 Resource Server — JWT Validation.

ADR Б2.1:
- forge-core-api validates JWT, caches JWKS with rotation.
- Mandatory: Protected Resource Metadata publication (RFC 9728).
- Reject on invalid iss/aud/exp → 401 invalid_token + audit_log entry.

This module exposes:
- ``validate_token(token, settings)``   — main validation entry point
- ``TokenClaims``                       — typed result of a successful validation
- ``TokenValidationError``              — raised on any token failure
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from jose import ExpiredSignatureError, JWTError, jwk, jwt

from forge_api.auth.jwks_cache import JWKSFetchError, get_key_by_kid
from forge_api.auth._audit import write_auth_audit_event
from forge_api.config import Settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class TokenValidationError(Exception):
    """Raised when a JWT fails any validation check.

    ``error_code`` is the OAuth 2.1 error code to return in the
    WWW-Authenticate header (e.g. ``invalid_token``, ``expired_token``).
    """

    def __init__(self, message: str, error_code: str = "invalid_token") -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class TokenClaims:
    """Typed, validated claims extracted from a good JWT.

    All fields mandatory per ADR Б2.1 Token Binding contract.
    """

    sub: str
    iss: str
    aud: str | list[str]
    exp: int
    job_id: str
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_kid(token: str) -> str:
    """Return the ``kid`` from an unverified JWT header.

    Raises:
        TokenValidationError: Header is malformed or missing kid.
    """
    try:
        headers = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise TokenValidationError(
            f"Malformed JWT header: {exc}", "invalid_token"
        ) from exc
    kid = headers.get("kid")
    if not kid:
        raise TokenValidationError(
            "JWT header missing 'kid' — cannot resolve signing key", "invalid_token"
        )
    return kid


async def _resolve_public_key(token: str, settings: Settings) -> Any:
    """Resolve the JWK public key for *token* using the JWKS cache.

    Raises:
        TokenValidationError: kid unknown or JWKS unreachable.
    """
    kid = _extract_kid(token)
    try:
        jwk_dict = await get_key_by_kid(settings.oauth_jwks_uri, kid)
    except KeyError:
        raise TokenValidationError(
            f"Unknown signing key kid={kid!r}; token rejected", "invalid_token"
        )
    except JWKSFetchError as exc:
        raise TokenValidationError(
            f"Cannot resolve signing keys: {exc}", "invalid_token"
        )

    try:
        return jwk.construct(jwk_dict)
    except Exception as exc:
        raise TokenValidationError(
            f"Failed to construct public key from JWK: {exc}", "invalid_token"
        ) from exc


# ---------------------------------------------------------------------------
# Main public entry point
# ---------------------------------------------------------------------------

async def validate_token(token: str, settings: Settings) -> TokenClaims:
    """Validate *token* as an OAuth 2.1 Bearer JWT.

    Steps (following ADR Б2.1):
    1. Resolve public key via JWKS cache (kid-based lookup + rotation).
    2. Verify signature, expiry, issuer, audience.
    3. Assert ``job_id`` claim is present.
    4. Return typed ``TokenClaims`` on success.

    On any failure: write to audit_log and raise ``TokenValidationError``.

    Args:
        token: Raw Bearer token string (without "Bearer " prefix).
        settings: Application settings (issuer, JWKS URI, audience).

    Returns:
        ``TokenClaims`` with validated, typed fields.

    Raises:
        TokenValidationError: Any validation failure. Caller maps to HTTP 401.
    """
    public_key = await _resolve_public_key(token, settings)

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key,
            algorithms=["RS256", "ES256"],
            audience=settings.oauth_audience,
            issuer=settings.oauth_issuer,
            options={"verify_exp": True},
        )
    except ExpiredSignatureError:
        await write_auth_audit_event(
            event="jwt_rejected",
            reason="expired",
            token_snippet=token[:16] + "…",
        )
        raise TokenValidationError("Token has expired", "expired_token")
    except JWTError as exc:
        await write_auth_audit_event(
            event="jwt_rejected",
            reason=str(exc),
            token_snippet=token[:16] + "…",
        )
        raise TokenValidationError(
            f"JWT validation failed: {exc}", "invalid_token"
        ) from exc

    # Mandatory: job_id claim must be present (ADR Б2.1 Token Binding)
    job_id: str | None = claims.get("job_id")
    if not job_id:
        await write_auth_audit_event(
            event="jwt_rejected",
            reason="missing_job_id_claim",
            token_snippet=token[:16] + "…",
        )
        raise TokenValidationError(
            "Token missing required 'job_id' claim", "invalid_token"
        )

    logger.debug(
        "JWT validated: sub=%s job_id=%s exp=%s",
        claims.get("sub"), job_id, claims.get("exp"),
    )

    return TokenClaims(
        sub=claims.get("sub", ""),
        iss=claims["iss"],
        aud=claims["aud"],
        exp=claims["exp"],
        job_id=job_id,
        raw=claims,
    )
