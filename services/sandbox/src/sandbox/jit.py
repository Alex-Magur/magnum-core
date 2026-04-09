import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Set


class ReplayDetected(Exception):
    """Exception raised when a token nonce reuse is detected."""
    pass


class TokenExpired(Exception):
    """Exception raised when a JIT token's TTL has expired."""
    pass


@dataclass(frozen=True, slots=True)
class JitToken:
    """
    Just-In-Time (JIT) Token for sandbox job authorization.
    Adheres to ADR 3.2.
    """
    token_id: str
    nonce: str
    sandbox_instance_id: str
    job_id: str
    spiffe_id: str
    issued_at: datetime
    ttl: int = 60

    def is_expired(self, current_time: datetime | None = None) -> bool:
        """
        Check if the token has exceeded its TTL.
        Uses UTC comparison.
        """
        now = current_time or datetime.now(timezone.utc)
        
        # Ensure issued_at is timezone-aware for comparison
        issued_at = self.issued_at
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
        
        return (now - issued_at).total_seconds() > self.ttl


class JitTokenStore:
    """
    Thread-safe in-memory store for tracking JIT token nonces to prevent replay attacks.
    """
    def __init__(self) -> None:
        self._used_nonces: Set[str] = set()
        self._lock = threading.Lock()

    def validate_and_record_nonce(self, token: JitToken) -> None:
        """
        Validates token freshness and records the nonce.
        
        Raises:
            TokenExpired: If the token is past its TTL.
            ReplayDetected: If the nonce has already been consumed.
        """
        if token.is_expired():
            raise TokenExpired(f"Token {token.token_id} expired (TTL: {token.ttl}s)")

        with self._lock:
            if token.nonce in self._used_nonces:
                raise ReplayDetected(f"Replay detected for nonce: {token.nonce}")
            self._used_nonces.add(token.nonce)

    def flush(self) -> None:
        """Clears all tracked nonces."""
        with self._lock:
            self._used_nonces.clear()
