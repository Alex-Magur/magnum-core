"""Token Binding — job_id claim verification.

ADR Б2.1:
- Access token contains claim `job_id`.
- Gateway rejects tokens not matching the active task context.
- Rejection → 403 + audit_log entry.

This module provides:
- ``verify_token_binding(claims, request_job_id)``  — raises on mismatch
- ``get_current_job_id(request)``                   — extract job_id from path/query
- ``require_auth``                                  — FastAPI dependency combining
                                                      JWT validation + binding check
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from forge_api.auth._audit import write_auth_audit_event
from forge_api.auth.oauth import TokenClaims, TokenValidationError, validate_token
from forge_api.config import settings as app_settings

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Token binding check
# ---------------------------------------------------------------------------

class TokenBindingError(Exception):
    """Raised when the token's job_id does not match the request context."""


async def verify_token_binding(claims: TokenClaims, request_job_id: str) -> None:
    """Assert that *claims.job_id* matches *request_job_id*.

    ADR Б2.1: "Gateway rejects a token whose job_id does not match the
    active task context."

    Args:
        claims:          Validated ``TokenClaims`` from ``validate_token``.
        request_job_id:  The job_id expected for this request
                         (extracted from the URL path or query parameter).

    Raises:
        TokenBindingError: job_id mismatch — caller maps to HTTP 403.
    """
    if claims.job_id != request_job_id:
        await write_auth_audit_event(
            event="token_binding_fail",
            reason="job_id_mismatch",
            actor=claims.sub,
            detail=f"token.job_id={claims.job_id!r} != request.job_id={request_job_id!r}",
        )
        raise TokenBindingError(
            f"Token job_id {claims.job_id!r} does not match "
            f"request job_id {request_job_id!r}"
        )

    logger.debug(
        "Token binding OK: sub=%s job_id=%s", claims.sub, claims.job_id
    )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> TokenClaims:
    """FastAPI dependency: validate Bearer JWT and optionally check job_id binding.

    Usage::

        @app.get("/jobs/{job_id}/...")
        async def endpoint(
            job_id: str,
            claims: TokenClaims = Depends(require_auth),
        ):
            ...

    The dependency:
    1. Extracts and validates the Bearer JWT (401 on failure).
    2. If the route contains a ``{job_id}`` path parameter, enforces
       token binding: token.job_id must equal path job_id (403 on mismatch).

    Args:
        request:     Current FastAPI request.
        credentials: Injected by HTTPBearer.

    Returns:
        Validated ``TokenClaims``.

    Raises:
        HTTPException 401: Missing or invalid token.
        HTTPException 403: Token binding failure.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    token = credentials.credentials

    try:
        claims = await validate_token(token, app_settings)
    except TokenValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="{exc.error_code}", '
                    f'error_description="{exc}"'
                )
            },
        ) from exc

    # Token binding: enforce only when route has a {job_id} path parameter
    request_job_id: str | None = request.path_params.get("job_id")
    if request_job_id is not None:
        try:
            await verify_token_binding(claims, request_job_id)
        except TokenBindingError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc

    return claims
