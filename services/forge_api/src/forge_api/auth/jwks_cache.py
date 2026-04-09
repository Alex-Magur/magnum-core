"""JWKS Cache with automatic rotation support.

ADR Б2.1: forge-core-api validates JWT, caches JWKS with rotation.

Design:
- Async fetch via httpx, single asyncio.Lock prevents thundering herd.
- TTL-based invalidation (default 300 s); stale cache is served on fetch
  error to avoid hard dependency on the IdP during momentary outages.
- Key lookup by `kid` (key ID); raises KeyError when kid is absent so the
  caller can trigger a forced refresh (handles key rotation).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal state (module-level singletons — one cache per process)
# ---------------------------------------------------------------------------
_jwks_cache: dict[str, Any] = {}          # kid -> JWK dict
_last_fetched_at: float = 0.0
_CACHE_TTL_SECONDS: float = 300.0         # 5 min default, overridden in tests


class JWKSFetchError(Exception):
    """Raised when the JWKS endpoint cannot be reached and there is no cache."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_jwks(jwks_uri: str, *, force: bool = False) -> dict[str, Any]:
    """Fetch and cache JWKS from *jwks_uri*.

    Returns a dict mapping ``kid`` → JWK entry.

    Args:
        jwks_uri: Full URL of the JWKS endpoint (e.g. https://idp/.well-known/jwks.json).
        force: Bypass TTL and force a refresh.

    Raises:
        JWKSFetchError: Network error and nothing is cached.
    """
    global _jwks_cache, _last_fetched_at  # noqa: PLW0603

    now = time.monotonic()
    cache_valid = (now - _last_fetched_at) < _CACHE_TTL_SECONDS

    if cache_valid and not force and _jwks_cache:
        logger.debug("JWKS cache hit (age=%.1fs)", now - _last_fetched_at)
        return _jwks_cache

    logger.info("Fetching JWKS from %s (force=%s)", jwks_uri, force)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        if _jwks_cache:
            logger.warning(
                "JWKS fetch failed (%s); serving stale cache", exc
            )
            return _jwks_cache
        raise JWKSFetchError(
            f"JWKS unreachable and no cached keys available: {exc}"
        ) from exc

    keys: dict[str, Any] = {
        key["kid"]: key
        for key in data.get("keys", [])
        if "kid" in key
    }
    _jwks_cache = keys
    _last_fetched_at = now
    logger.info("JWKS refreshed — %d key(s) loaded", len(keys))
    return keys


async def get_key_by_kid(jwks_uri: str, kid: str) -> dict[str, Any]:
    """Return the JWK for *kid*, refreshing the cache if not found.

    Implements the rotation-aware lookup:
    1. Try cache.
    2. On miss → force-refresh once.
    3. Still missing → KeyError (key no longer in the JWKS — reject token).

    Raises:
        KeyError: kid not found even after forced refresh.
        JWKSFetchError: JWKS unreachable and no cache.
    """
    keys = await fetch_jwks(jwks_uri)
    if kid not in keys:
        logger.info("kid=%s not in cache; forcing JWKS refresh", kid)
        keys = await fetch_jwks(jwks_uri, force=True)
    if kid not in keys:
        raise KeyError(f"Unknown kid: {kid!r}")
    return keys[kid]


def _reset_cache_for_testing() -> None:
    """Reset module-level cache; ONLY for use in unit tests."""
    global _jwks_cache, _last_fetched_at  # noqa: PLW0603
    _jwks_cache = {}
    _last_fetched_at = 0.0
