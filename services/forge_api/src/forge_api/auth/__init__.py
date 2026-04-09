"""OAuth 2.1 authentication module.

ADR References:
  - Б2.1: OIDC/OAuth 2.1 Resource Server (Class A)
  - JWT validation, JWKS caching with rotation
  - RFC 9728: Protected Resource Metadata publication

Public API:
  - validate_token(token, settings) -> TokenClaims
  - TokenClaims
  - TokenValidationError
  - require_auth  (FastAPI Dependency)
  - verify_token_binding(claims, job_id)
  - fetch_jwks(uri), get_key_by_kid(uri, kid)
"""

from forge_api.auth.jwks_cache import JWKSFetchError, fetch_jwks, get_key_by_kid
from forge_api.auth.oauth import TokenClaims, TokenValidationError, validate_token
from forge_api.auth.token_binding import (
    TokenBindingError,
    require_auth,
    verify_token_binding,
)

__all__ = [
    "JWKSFetchError",
    "TokenBindingError",
    "TokenClaims",
    "TokenValidationError",
    "fetch_jwks",
    "get_key_by_kid",
    "require_auth",
    "validate_token",
    "verify_token_binding",
]
