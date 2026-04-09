import threading
import time
from datetime import datetime, timezone, timedelta
import pytest
from sandbox.jit import JitToken, JitTokenStore, ReplayDetected, TokenExpired


def test_jit_token_expiration():
    """Verify that JitToken correctly identifies expiration."""
    now = datetime.now(timezone.utc)
    
    fresh_token = JitToken(
        token_id="t1", nonce="n1", sandbox_instance_id="s1",
        job_id="j1", spiffe_id="sp1", issued_at=now, ttl=60
    )
    assert fresh_token.is_expired() is False
    
    expired_token = JitToken(
        token_id="t2", nonce="n2", sandbox_instance_id="s1",
        job_id="j1", spiffe_id="sp1",
        issued_at=now - timedelta(seconds=61), ttl=60
    )
    assert expired_token.is_expired() is True


def test_jit_token_store_replay():
    """Verify that JitTokenStore blocks nonce reuse."""
    store = JitTokenStore()
    now = datetime.now(timezone.utc)
    
    token = JitToken(
        token_id="t1", nonce="unique_nonce", sandbox_instance_id="s1",
        job_id="j1", spiffe_id="sp1", issued_at=now
    )
    
    # First use: Success
    store.validate_and_record_nonce(token)
    
    # Second use: ReplayDetected
    with pytest.raises(ReplayDetected, match="Replay detected"):
        store.validate_and_record_nonce(token)


def test_jit_token_store_expiration():
    """Verify that JitTokenStore blocks expired tokens."""
    store = JitTokenStore()
    expired_time = datetime.now(timezone.utc) - timedelta(seconds=120)
    
    token = JitToken(
        token_id="t1", nonce="nonce1", sandbox_instance_id="s1",
        job_id="j1", spiffe_id="sp1", issued_at=expired_time
    )
    
    with pytest.raises(TokenExpired, match="expired"):
        store.validate_and_record_nonce(token)


def test_jit_token_store_thread_safety():
    """Verify that multiple threads can safely interact with the store."""
    store = JitTokenStore()
    now = datetime.now(timezone.utc)
    nonces_to_add = 100
    
    def worker(nonce_id: int):
        token = JitToken(
            token_id=f"t{nonce_id}", nonce=f"nonce_{nonce_id}",
            sandbox_instance_id="s1", job_id="j1", spiffe_id="sp1",
            issued_at=now
        )
        store.validate_and_record_nonce(token)

    threads = []
    for i in range(nonces_to_add):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    with store._lock:
        assert len(store._used_nonces) == nonces_to_add
